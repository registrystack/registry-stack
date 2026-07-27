// SPDX-License-Identifier: Apache-2.0
//! Stable, value-free Registry Notary runtime activation codes.

use std::fmt;

use super::assembly::StandaloneServerError;
use crate::state_plane::{NotaryPostgresStatePlaneReadiness, SensitiveStateError};

const VALUE_FREE_EVIDENCE_POLICY: &str = "Emit only this code and static definition. Do not emit inner errors, paths, URLs, hashes, credentials, identifiers, parser text, or country values.";
const ACTIVATION_EVIDENCE_LIMITATION: &str = "The category confirms only the failed activation boundary; it does not disclose paths, URLs, hashes, credentials, identifiers, parser text, authored values, source responses, or country values.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum NotaryActivationCodeKind {
    CelWorkerUnavailable,
    ConfigurationInvalid,
    DeploymentGateFailed,
    RelayActivationFailed,
    RelayConfigurationInvalid,
    RelayCredentialUnavailable,
    RelayCredentialsRejected,
    RelayProfileMismatch,
    RelayProfileNotFound,
    RelayUnavailable,
    RuntimeActivationFailed,
    RuntimeActivationRequired,
    PostgresqlDatabaseReadOnly,
    PostgresqlDatabaseUnavailable,
    PostgresqlDatabaseUnsupported,
    PostgresqlDurabilityUnsafe,
    PostgresqlRoleIncompatible,
    PostgresqlSchemaIncompatible,
}

/// Closed, product-owned code for a Registry Notary runtime activation failure.
///
/// The representation is private so callers cannot invent codes. Use the
/// named constants or [`Self::ALL`] when building operator references.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotaryActivationCode(NotaryActivationCodeKind);

impl NotaryActivationCode {
    pub const CEL_WORKER_UNAVAILABLE: Self = Self(NotaryActivationCodeKind::CelWorkerUnavailable);
    pub const CONFIGURATION_INVALID: Self = Self(NotaryActivationCodeKind::ConfigurationInvalid);
    pub const DEPLOYMENT_GATE_FAILED: Self = Self(NotaryActivationCodeKind::DeploymentGateFailed);
    pub const RELAY_ACTIVATION_FAILED: Self = Self(NotaryActivationCodeKind::RelayActivationFailed);
    pub const RELAY_CONFIGURATION_INVALID: Self =
        Self(NotaryActivationCodeKind::RelayConfigurationInvalid);
    pub const RELAY_CREDENTIAL_UNAVAILABLE: Self =
        Self(NotaryActivationCodeKind::RelayCredentialUnavailable);
    pub const RELAY_CREDENTIALS_REJECTED: Self =
        Self(NotaryActivationCodeKind::RelayCredentialsRejected);
    pub const RELAY_PROFILE_MISMATCH: Self = Self(NotaryActivationCodeKind::RelayProfileMismatch);
    pub const RELAY_PROFILE_NOT_FOUND: Self = Self(NotaryActivationCodeKind::RelayProfileNotFound);
    pub const RELAY_UNAVAILABLE: Self = Self(NotaryActivationCodeKind::RelayUnavailable);
    pub const RUNTIME_ACTIVATION_FAILED: Self =
        Self(NotaryActivationCodeKind::RuntimeActivationFailed);
    pub const RUNTIME_ACTIVATION_REQUIRED: Self =
        Self(NotaryActivationCodeKind::RuntimeActivationRequired);
    pub const POSTGRESQL_DATABASE_READ_ONLY: Self =
        Self(NotaryActivationCodeKind::PostgresqlDatabaseReadOnly);
    pub const POSTGRESQL_DATABASE_UNAVAILABLE: Self =
        Self(NotaryActivationCodeKind::PostgresqlDatabaseUnavailable);
    pub const POSTGRESQL_DATABASE_UNSUPPORTED: Self =
        Self(NotaryActivationCodeKind::PostgresqlDatabaseUnsupported);
    pub const POSTGRESQL_DURABILITY_UNSAFE: Self =
        Self(NotaryActivationCodeKind::PostgresqlDurabilityUnsafe);
    pub const POSTGRESQL_ROLE_INCOMPATIBLE: Self =
        Self(NotaryActivationCodeKind::PostgresqlRoleIncompatible);
    pub const POSTGRESQL_SCHEMA_INCOMPATIBLE: Self =
        Self(NotaryActivationCodeKind::PostgresqlSchemaIncompatible);

    /// Every published code in stable lexical order.
    pub const ALL: &'static [Self] = &[
        Self::CEL_WORKER_UNAVAILABLE,
        Self::CONFIGURATION_INVALID,
        Self::DEPLOYMENT_GATE_FAILED,
        Self::RELAY_ACTIVATION_FAILED,
        Self::RELAY_CONFIGURATION_INVALID,
        Self::RELAY_CREDENTIAL_UNAVAILABLE,
        Self::RELAY_CREDENTIALS_REJECTED,
        Self::RELAY_PROFILE_MISMATCH,
        Self::RELAY_PROFILE_NOT_FOUND,
        Self::RELAY_UNAVAILABLE,
        Self::RUNTIME_ACTIVATION_FAILED,
        Self::RUNTIME_ACTIVATION_REQUIRED,
        Self::POSTGRESQL_DATABASE_READ_ONLY,
        Self::POSTGRESQL_DATABASE_UNAVAILABLE,
        Self::POSTGRESQL_DATABASE_UNSUPPORTED,
        Self::POSTGRESQL_DURABILITY_UNSAFE,
        Self::POSTGRESQL_ROLE_INCOMPATIBLE,
        Self::POSTGRESQL_SCHEMA_INCOMPATIBLE,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            NotaryActivationCodeKind::CelWorkerUnavailable => "notary.cel.worker_unavailable",
            NotaryActivationCodeKind::ConfigurationInvalid => "notary.configuration.invalid",
            NotaryActivationCodeKind::DeploymentGateFailed => "notary.deployment.gate_failed",
            NotaryActivationCodeKind::RelayActivationFailed => "notary.relay.activation_failed",
            NotaryActivationCodeKind::RelayConfigurationInvalid => {
                "notary.relay.configuration_invalid"
            }
            NotaryActivationCodeKind::RelayCredentialUnavailable => {
                "notary.relay.credential_unavailable"
            }
            NotaryActivationCodeKind::RelayCredentialsRejected => {
                "notary.relay.credentials_rejected"
            }
            NotaryActivationCodeKind::RelayProfileMismatch => "notary.relay.profile_mismatch",
            NotaryActivationCodeKind::RelayProfileNotFound => "notary.relay.profile_not_found",
            NotaryActivationCodeKind::RelayUnavailable => "notary.relay.unavailable",
            NotaryActivationCodeKind::RuntimeActivationFailed => "notary.runtime.activation_failed",
            NotaryActivationCodeKind::RuntimeActivationRequired => {
                "notary.runtime.activation_required"
            }
            NotaryActivationCodeKind::PostgresqlDatabaseReadOnly => {
                "notary.state.postgresql.database_read_only"
            }
            NotaryActivationCodeKind::PostgresqlDatabaseUnavailable => {
                "notary.state.postgresql.database_unavailable"
            }
            NotaryActivationCodeKind::PostgresqlDatabaseUnsupported => {
                "notary.state.postgresql.database_unsupported"
            }
            NotaryActivationCodeKind::PostgresqlDurabilityUnsafe => {
                "notary.state.postgresql.durability_unsafe"
            }
            NotaryActivationCodeKind::PostgresqlRoleIncompatible => {
                "notary.state.postgresql.role_incompatible"
            }
            NotaryActivationCodeKind::PostgresqlSchemaIncompatible => {
                "notary.state.postgresql.schema_incompatible"
            }
        }
    }

    /// Static value-free operator guidance for this code.
    #[must_use]
    pub fn definition(self) -> &'static NotaryActivationCodeDefinition {
        &NOTARY_ACTIVATION_CODE_DEFINITIONS[self.0 as usize]
    }
}

impl fmt::Display for NotaryActivationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Publication state for a product-owned activation code definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotaryActivationCodeLifecycle {
    /// The catalog contract has not shipped in a tagged release.
    Unreleased,
    /// The catalog contract shipped in the named release.
    Released { introduced_version: &'static str },
}

impl NotaryActivationCodeLifecycle {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreleased => "unreleased",
            Self::Released { .. } => "released",
        }
    }

    #[must_use]
    pub const fn introduced_version(self) -> Option<&'static str> {
        match self {
            Self::Unreleased => None,
            Self::Released { introduced_version } => Some(introduced_version),
        }
    }
}

/// Static, value-free meaning and recovery guidance for an activation code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotaryActivationCodeDefinition {
    pub code: NotaryActivationCode,
    pub lifecycle: NotaryActivationCodeLifecycle,
    pub phase: &'static str,
    pub meaning: &'static str,
    pub rule: &'static str,
    pub remediation: &'static str,
    pub evidence_scope: &'static str,
    pub evidence_policy: &'static str,
    pub evidence_limitation: &'static str,
    pub docs_slug: &'static str,
}

/// Product-owned source for generated operator references.
pub static NOTARY_ACTIVATION_CODE_DEFINITIONS: [NotaryActivationCodeDefinition; 18] = [
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::CEL_WORKER_UNAVAILABLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary CEL worker is unavailable",
        rule: "Every configured CEL worker must complete the bounded product protocol probe before listeners serve",
        remediation: "verify that the adjacent CEL worker artifact is present and executable, confirm the supported platform and configured resource ceilings, then retry activation",
        evidence_scope: "CEL worker packaging, protocol responsiveness, supported platform, and bounded startup capacity",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "cel-worker-unavailable",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::CONFIGURATION_INVALID,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "configuration_activation",
        meaning: "Registry Notary runtime configuration is invalid",
        rule: "Runtime activation requires valid product configuration, supported features, and resolvable secret and provider bindings",
        remediation: "run registry-notary doctor, correct the reviewed configuration or binding, and retry activation",
        evidence_scope: "Notary configuration, provider bindings, and compiled feature support",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "configuration-invalid",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::DEPLOYMENT_GATE_FAILED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "deployment_activation",
        meaning: "Registry Notary deployment gates refused startup",
        rule: "Every startup-failing deployment gate must pass before activation",
        remediation: "run registry-notary doctor for the selected deployment profile and resolve its startup-failing findings",
        evidence_scope: "selected deployment profile and startup-failing gate results",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "deployment-gate-failed",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_ACTIVATION_FAILED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay consultation activation failed",
        rule: "Registry-backed claims require the reviewed Relay consultation client to activate before Notary serves",
        remediation: "check the Notary configuration and startup environment",
        evidence_scope: "Notary Relay consultation client activation lifecycle",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-activation-failed",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay consultation configuration is invalid",
        rule: "The Relay destination, activation plan, and activation lifecycle must form one valid reviewed configuration",
        remediation: "check the evidence.relay connection and Registry-backed consultation configuration",
        evidence_scope: "Relay destination, activation plan, and consultation configuration",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-configuration-invalid",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_CREDENTIAL_UNAVAILABLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay workload credential is unavailable",
        rule: "A current non-empty workload credential must be available before a live Relay consultation",
        remediation: "mount a current readable workload JWT at evidence.relay.token_file",
        evidence_scope: "configured Relay workload credential availability",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-credential-unavailable",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_CREDENTIALS_REJECTED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay rejected the configured workload credential",
        rule: "Relay must accept the configured Notary workload binding, scope, and validity window",
        remediation: "rotate the workload JWT and verify that Relay recognizes its workload binding, required scope, and validity window",
        evidence_scope: "Relay workload binding, scope, and validity acceptance",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-credentials-rejected",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_PROFILE_MISMATCH,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay consultation profile does not match the configured contract pin",
        rule: "The active Relay profile must match the reviewed Notary consultation contract pin",
        remediation: "reconcile the Notary profile id and contract hash with the reviewed Relay consultation contract",
        evidence_scope: "reviewed Notary profile pin and active Relay consultation contract",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-profile-mismatch",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_PROFILE_NOT_FOUND,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay consultation profile was not found",
        rule: "Every Registry-backed Notary consultation must resolve to an active Relay profile",
        remediation: "deploy the configured Relay profile id, then retry the live check",
        evidence_scope: "configured consultation profile resolution in Relay",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-profile-not-found",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RELAY_UNAVAILABLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "relay_activation",
        meaning: "Relay consultation service is unavailable",
        rule: "The reviewed Relay destination must be reachable through the configured transport policy",
        remediation: "check Relay reachability, TLS, destination policy, and service health",
        evidence_scope: "reviewed Relay destination, transport policy, and service availability",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "relay-unavailable",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RUNTIME_ACTIVATION_FAILED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary runtime activation failed",
        rule: "Audit, state, sensitive-state, and other runtime dependencies must activate successfully before listeners serve",
        remediation: "restore the governed runtime dependency or integrity condition, then retry activation",
        evidence_scope: "governed audit, state, sensitive-state, and runtime dependencies",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "runtime-activation-failed",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::RUNTIME_ACTIVATION_REQUIRED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary runtime activation is required before serving",
        rule: "Routers may be built only after the governed audit and state activation lifecycle completes",
        remediation: "run the compiled Registry Notary runtime activation step before building or serving routers",
        evidence_scope: "router assembly and governed audit and state activation lifecycle",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "runtime-activation-required",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_DATABASE_READ_ONLY,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL state database is read-only or recovering",
        rule: "Serving requires a writable PostgreSQL primary for correctness-state transactions",
        remediation: "restore a writable PostgreSQL primary, run registry-notary state doctor, and retry activation",
        evidence_scope: "PostgreSQL writeability and recovery posture",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-database-read-only",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL state database is unavailable",
        rule: "Serving requires a reachable PostgreSQL service with an accepted TLS trust chain",
        remediation: "check PostgreSQL reachability, TLS trust, and service health, then run registry-notary state doctor",
        evidence_scope: "PostgreSQL transport, TLS trust, and service availability",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-database-unavailable",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_DATABASE_UNSUPPORTED,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL server major is unsupported",
        rule: "Serving requires a PostgreSQL major covered by the Registry Notary compatibility contract",
        remediation: "move the state database to a supported PostgreSQL major, run registry-notary state doctor, and retry activation",
        evidence_scope: "PostgreSQL server-major compatibility",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-database-unsupported",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_DURABILITY_UNSAFE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL durability settings are unsafe",
        rule: "Serving requires the documented PostgreSQL durability settings for correctness state",
        remediation: "restore the required PostgreSQL durability settings, run registry-notary state doctor, and retry activation",
        evidence_scope: "PostgreSQL durability posture",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-durability-unsafe",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_ROLE_INCOMPATIBLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL runtime role contract is incompatible",
        rule: "Serving requires the documented restricted runtime role and its attested schema binding",
        remediation: "restore the documented runtime grants and role binding, run registry-notary state doctor, and retry activation",
        evidence_scope: "PostgreSQL runtime-role attributes, grants, and schema binding",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-role-incompatible",
    },
    NotaryActivationCodeDefinition {
        code: NotaryActivationCode::POSTGRESQL_SCHEMA_INCOMPATIBLE,
        lifecycle: NotaryActivationCodeLifecycle::Unreleased,
        phase: "runtime_activation",
        meaning: "Registry Notary PostgreSQL state schema contract is incompatible",
        rule: "Serving requires the exact product-owned schema, catalog, fingerprint, and privilege contract",
        remediation: "restore or install the matching Registry Notary state schema, run registry-notary state doctor, and retry activation",
        evidence_scope: "PostgreSQL state schema, catalog, fingerprint, and privilege contract",
        evidence_policy: VALUE_FREE_EVIDENCE_POLICY,
        evidence_limitation: ACTIVATION_EVIDENCE_LIMITATION,
        docs_slug: "postgresql-schema-incompatible",
    },
];

impl NotaryPostgresStatePlaneReadiness {
    /// Map a value-free PostgreSQL readiness classification to its public
    /// activation code and static operator guidance.
    #[must_use]
    pub const fn activation_code(self) -> NotaryActivationCode {
        match self {
            Self::ConfigurationInvalid => NotaryActivationCode::CONFIGURATION_INVALID,
            Self::DatabaseUnavailable | Self::Shutdown => {
                NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE
            }
            Self::UnsupportedServerMajor => NotaryActivationCode::POSTGRESQL_DATABASE_UNSUPPORTED,
            Self::DatabaseNotWritable => NotaryActivationCode::POSTGRESQL_DATABASE_READ_ONLY,
            Self::UnsafeDurability => NotaryActivationCode::POSTGRESQL_DURABILITY_UNSAFE,
            Self::SchemaIncompatible => NotaryActivationCode::POSTGRESQL_SCHEMA_INCOMPATIBLE,
            Self::RoleIncompatible => NotaryActivationCode::POSTGRESQL_ROLE_INCOMPATIBLE,
            Self::Ready => NotaryActivationCode::RUNTIME_ACTIVATION_FAILED,
        }
    }
}

/// Redacted process-boundary error that deliberately retains no inner error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotaryActivationFailure {
    code: NotaryActivationCode,
}

impl NotaryActivationFailure {
    #[must_use]
    pub const fn code(self) -> NotaryActivationCode {
        self.code
    }

    #[must_use]
    pub fn definition(self) -> &'static NotaryActivationCodeDefinition {
        self.code.definition()
    }
}

impl fmt::Debug for NotaryActivationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotaryActivationFailure")
            .field("code", &self.code.as_str())
            .finish()
    }
}

impl fmt::Display for NotaryActivationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let definition = self.definition();
        write!(
            formatter,
            "{}: {}; next action: {}",
            definition.code, definition.meaning, definition.remediation
        )
    }
}

impl std::error::Error for NotaryActivationFailure {}

impl From<NotaryActivationCode> for NotaryActivationFailure {
    fn from(code: NotaryActivationCode) -> Self {
        Self { code }
    }
}

impl From<StandaloneServerError> for NotaryActivationFailure {
    fn from(error: StandaloneServerError) -> Self {
        error.activation_code().into()
    }
}

impl StandaloneServerError {
    /// Map every internal startup failure to a closed, value-free public code.
    #[must_use]
    pub const fn activation_code(&self) -> NotaryActivationCode {
        match self {
            Self::Config(_)
            | Self::MissingCredentialEnv(_)
            | Self::InvalidCredentialHash(_, _)
            | Self::InvalidSigningKey { .. }
            | Self::SigningKeyProviderUnavailable { .. }
            | Self::MissingFederationSecretEnv(_)
            | Self::MissingAuditPath
            | Self::MissingAuditHashSecretEnv
            | Self::Cors(_)
            | Self::InvalidAuditSink(_)
            | Self::InvalidAuditConfig(_)
            | Self::InvalidOidcConfig(_)
            | Self::InvalidFederationConfig(_) => NotaryActivationCode::CONFIGURATION_INVALID,
            Self::InvalidRelayDestination
            | Self::InvalidRelayActivationPlan
            | Self::RelayAlreadyActivated
            | Self::RelayNotActivated => NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
            Self::RelayActivation => NotaryActivationCode::RELAY_ACTIVATION_FAILED,
            Self::RelayCredentialUnavailable => NotaryActivationCode::RELAY_CREDENTIAL_UNAVAILABLE,
            Self::RelayCredentialsRejected => NotaryActivationCode::RELAY_CREDENTIALS_REJECTED,
            Self::RelayProfileNotFound => NotaryActivationCode::RELAY_PROFILE_NOT_FOUND,
            Self::RelayProfileMismatch => NotaryActivationCode::RELAY_PROFILE_MISMATCH,
            Self::RelayUnavailable => NotaryActivationCode::RELAY_UNAVAILABLE,
            Self::AuditChainVerificationRequired | Self::PostgresqlStateActivationRequired => {
                NotaryActivationCode::RUNTIME_ACTIVATION_REQUIRED
            }
            Self::StatePlane(error) => {
                NotaryPostgresStatePlaneReadiness::from_error(*error).activation_code()
            }
            Self::SensitiveState(SensitiveStateError::StatePlane(error)) => {
                NotaryPostgresStatePlaneReadiness::from_error(*error).activation_code()
            }
            Self::Audit(_) | Self::SensitiveState(_) => {
                NotaryActivationCode::RUNTIME_ACTIVATION_FAILED
            }
            #[cfg(feature = "registry-notary-cel")]
            Self::InvalidCelConfig(_) => NotaryActivationCode::CONFIGURATION_INVALID,
            #[cfg(feature = "registry-notary-cel")]
            Self::CelWorkerUnavailable => NotaryActivationCode::CEL_WORKER_UNAVAILABLE,
            Self::DeploymentGateStartupFailure { .. } => {
                NotaryActivationCode::DEPLOYMENT_GATE_FAILED
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use registry_notary_core::EvidenceConfigError;
    use registry_platform_audit::AuditError;
    use registry_platform_authcommon::FingerprintFormatError;
    use registry_platform_httpsec::CorsValidationError;

    use crate::state_plane::{NotaryPostgresStatePlaneError, SensitiveStateError};

    const SENTINEL: &str = "SENTINEL_PATH_URL_HASH_CREDENTIAL_IDENTIFIER_COUNTRY_PARSER_VALUE";

    fn representative_errors() -> Vec<(StandaloneServerError, NotaryActivationCode)> {
        let errors = vec![
            (
                StandaloneServerError::Config(EvidenceConfigError::InvalidAuthConfig {
                    reason: SENTINEL.to_string(),
                }),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::MissingCredentialEnv(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidCredentialHash(
                    SENTINEL.to_string(),
                    FingerprintFormatError::InvalidHex,
                ),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidRelayDestination,
                NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidRelayActivationPlan,
                NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::RelayActivation,
                NotaryActivationCode::RELAY_ACTIVATION_FAILED,
            ),
            (
                StandaloneServerError::RelayAlreadyActivated,
                NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::RelayNotActivated,
                NotaryActivationCode::RELAY_CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::AuditChainVerificationRequired,
                NotaryActivationCode::RUNTIME_ACTIVATION_REQUIRED,
            ),
            (
                StandaloneServerError::PostgresqlStateActivationRequired,
                NotaryActivationCode::RUNTIME_ACTIVATION_REQUIRED,
            ),
            (
                StandaloneServerError::RelayCredentialUnavailable,
                NotaryActivationCode::RELAY_CREDENTIAL_UNAVAILABLE,
            ),
            (
                StandaloneServerError::RelayCredentialsRejected,
                NotaryActivationCode::RELAY_CREDENTIALS_REJECTED,
            ),
            (
                StandaloneServerError::RelayProfileNotFound,
                NotaryActivationCode::RELAY_PROFILE_NOT_FOUND,
            ),
            (
                StandaloneServerError::RelayProfileMismatch,
                NotaryActivationCode::RELAY_PROFILE_MISMATCH,
            ),
            (
                StandaloneServerError::RelayUnavailable,
                NotaryActivationCode::RELAY_UNAVAILABLE,
            ),
            (
                StandaloneServerError::InvalidSigningKey {
                    key: SENTINEL.to_string(),
                    reason: SENTINEL.to_string(),
                },
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::SigningKeyProviderUnavailable {
                    provider: SENTINEL.to_string(),
                },
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::MissingFederationSecretEnv(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::MissingAuditPath,
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::MissingAuditHashSecretEnv,
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::Audit(AuditError::EnvVarUnavailable {
                    name: SENTINEL.to_string(),
                }),
                NotaryActivationCode::RUNTIME_ACTIVATION_FAILED,
            ),
            (
                StandaloneServerError::Cors(CorsValidationError::MalformedOrigin(
                    SENTINEL.to_string(),
                )),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidAuditSink(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidAuditConfig(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidOidcConfig(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::InvalidFederationConfig(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ),
            (
                StandaloneServerError::StatePlane(
                    NotaryPostgresStatePlaneError::DatabaseUrlUnavailable,
                ),
                NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE,
            ),
            (
                StandaloneServerError::SensitiveState(
                    SensitiveStateError::KeyEnvironmentUnavailable,
                ),
                NotaryActivationCode::RUNTIME_ACTIVATION_FAILED,
            ),
            (
                StandaloneServerError::DeploymentGateStartupFailure {
                    profile: SENTINEL.to_string(),
                    findings: SENTINEL.to_string(),
                },
                NotaryActivationCode::DEPLOYMENT_GATE_FAILED,
            ),
        ];
        #[cfg(feature = "registry-notary-cel")]
        let errors = {
            let mut errors = errors;
            errors.push((
                StandaloneServerError::InvalidCelConfig(SENTINEL.to_string()),
                NotaryActivationCode::CONFIGURATION_INVALID,
            ));
            errors.push((
                StandaloneServerError::CelWorkerUnavailable,
                NotaryActivationCode::CEL_WORKER_UNAVAILABLE,
            ));
            errors
        };
        errors
    }

    #[test]
    fn activation_codes_are_unique_ordered_and_definition_complete() {
        assert_eq!(
            NotaryActivationCode::ALL.len(),
            NOTARY_ACTIVATION_CODE_DEFINITIONS.len()
        );
        let mut docs_slugs = BTreeSet::new();
        for pair in NotaryActivationCode::ALL.windows(2) {
            assert!(
                pair[0].as_str() < pair[1].as_str(),
                "activation codes must remain unique and lexically ordered"
            );
        }
        for (index, code) in NotaryActivationCode::ALL.iter().copied().enumerate() {
            let definition = code.definition();
            assert_eq!(definition, &NOTARY_ACTIVATION_CODE_DEFINITIONS[index]);
            assert_eq!(definition.code, code);
            assert_eq!(
                definition.lifecycle,
                NotaryActivationCodeLifecycle::Unreleased
            );
            assert_eq!(definition.lifecycle.as_str(), "unreleased");
            assert_eq!(definition.lifecycle.introduced_version(), None);
            assert!(matches!(
                definition.phase,
                "configuration_activation"
                    | "deployment_activation"
                    | "relay_activation"
                    | "runtime_activation"
            ));
            assert!(!definition.meaning.is_empty());
            assert!(!definition.rule.is_empty());
            assert!(!definition.remediation.is_empty());
            assert!(!definition.evidence_scope.is_empty());
            assert_eq!(definition.evidence_policy, VALUE_FREE_EVIDENCE_POLICY);
            assert_eq!(
                definition.evidence_limitation,
                ACTIVATION_EVIDENCE_LIMITATION
            );
            assert!(
                !definition.docs_slug.is_empty()
                    && !definition.docs_slug.starts_with('-')
                    && !definition.docs_slug.ends_with('-')
                    && definition
                        .docs_slug
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'),
                "documentation slugs must be stable lowercase anchor components"
            );
            assert!(
                docs_slugs.insert(definition.docs_slug),
                "documentation slugs must be unique"
            );
            for value in [
                definition.phase,
                definition.meaning,
                definition.rule,
                definition.remediation,
                definition.evidence_scope,
                definition.evidence_policy,
                definition.evidence_limitation,
                definition.docs_slug,
            ] {
                assert!(
                    !value.contains(SENTINEL),
                    "static activation metadata must not carry runtime values"
                );
            }
        }
    }

    #[test]
    fn every_standalone_error_maps_to_a_published_value_free_code() {
        let cases = representative_errors();
        #[cfg(not(feature = "registry-notary-cel"))]
        assert_eq!(cases.len(), 29);
        #[cfg(feature = "registry-notary-cel")]
        assert_eq!(cases.len(), 31);

        for (error, expected) in cases {
            assert_eq!(error.activation_code(), expected);
            assert!(NotaryActivationCode::ALL.contains(&expected));
            let failure = NotaryActivationFailure::from(error);
            assert_eq!(failure.code(), expected);
            let display = failure.to_string();
            let debug = format!("{failure:?}");
            assert!(display.contains(expected.as_str()));
            assert!(!display.contains(SENTINEL));
            assert!(!debug.contains(SENTINEL));
        }
    }

    #[test]
    fn postgresql_failures_keep_cause_specific_public_classification() {
        let cases = [
            (
                NotaryPostgresStatePlaneError::DatabaseUnavailable,
                NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE,
            ),
            (
                NotaryPostgresStatePlaneError::DatabaseNotWritable,
                NotaryActivationCode::POSTGRESQL_DATABASE_READ_ONLY,
            ),
            (
                NotaryPostgresStatePlaneError::UnsupportedServerMajor,
                NotaryActivationCode::POSTGRESQL_DATABASE_UNSUPPORTED,
            ),
            (
                NotaryPostgresStatePlaneError::UnsafeDurability,
                NotaryActivationCode::POSTGRESQL_DURABILITY_UNSAFE,
            ),
            (
                NotaryPostgresStatePlaneError::SchemaIncompatible,
                NotaryActivationCode::POSTGRESQL_SCHEMA_INCOMPATIBLE,
            ),
            (
                NotaryPostgresStatePlaneError::RoleIncompatible,
                NotaryActivationCode::POSTGRESQL_ROLE_INCOMPATIBLE,
            ),
        ];

        for (error, expected) in cases {
            let direct = StandaloneServerError::StatePlane(error);
            let sensitive =
                StandaloneServerError::SensitiveState(SensitiveStateError::StatePlane(error));
            assert_eq!(direct.activation_code(), expected);
            assert_eq!(sensitive.activation_code(), expected);

            let failure = NotaryActivationFailure::from(direct);
            let rendered = format!("{failure:?} {failure}");
            assert!(rendered.contains(expected.as_str()));
            assert!(!rendered.contains(SENTINEL));
            assert!(!rendered.contains("postgresql://"));
        }
    }

    #[test]
    fn postgresql_public_diagnostics_have_static_meaning_and_remediation() {
        let codes = [
            NotaryActivationCode::POSTGRESQL_DATABASE_READ_ONLY,
            NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE,
            NotaryActivationCode::POSTGRESQL_DATABASE_UNSUPPORTED,
            NotaryActivationCode::POSTGRESQL_DURABILITY_UNSAFE,
            NotaryActivationCode::POSTGRESQL_ROLE_INCOMPATIBLE,
            NotaryActivationCode::POSTGRESQL_SCHEMA_INCOMPATIBLE,
        ];

        for code in codes {
            let definition = code.definition();
            let failure = NotaryActivationFailure::from(code);
            let display = failure.to_string();
            assert!(display.contains(code.as_str()));
            assert!(display.contains(definition.meaning));
            assert!(display.contains(definition.remediation));
            for forbidden in [SENTINEL, "postgresql://", "/run/", "registry_notary_"] {
                assert!(
                    !display.contains(forbidden),
                    "public PostgreSQL diagnostic exposed forbidden value {forbidden:?}: {display}"
                );
            }
        }
    }

    #[test]
    fn established_doctor_code_strings_remain_exact() {
        assert_eq!(
            NotaryActivationCode::RELAY_CREDENTIAL_UNAVAILABLE.as_str(),
            "notary.relay.credential_unavailable"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_CREDENTIALS_REJECTED.as_str(),
            "notary.relay.credentials_rejected"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_PROFILE_NOT_FOUND.as_str(),
            "notary.relay.profile_not_found"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_PROFILE_MISMATCH.as_str(),
            "notary.relay.profile_mismatch"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_UNAVAILABLE.as_str(),
            "notary.relay.unavailable"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_CONFIGURATION_INVALID.as_str(),
            "notary.relay.configuration_invalid"
        );
        assert_eq!(
            NotaryActivationCode::RELAY_ACTIVATION_FAILED.as_str(),
            "notary.relay.activation_failed"
        );
        assert_eq!(
            NotaryActivationCode::POSTGRESQL_DATABASE_READ_ONLY.as_str(),
            "notary.state.postgresql.database_read_only"
        );
        assert_eq!(
            NotaryActivationCode::POSTGRESQL_DATABASE_UNAVAILABLE.as_str(),
            "notary.state.postgresql.database_unavailable"
        );
        assert_eq!(
            NotaryActivationCode::POSTGRESQL_DATABASE_UNSUPPORTED.as_str(),
            "notary.state.postgresql.database_unsupported"
        );
        assert_eq!(
            NotaryActivationCode::POSTGRESQL_ROLE_INCOMPATIBLE.as_str(),
            "notary.state.postgresql.role_incompatible"
        );
        assert_eq!(
            NotaryActivationCode::POSTGRESQL_SCHEMA_INCOMPATIBLE.as_str(),
            "notary.state.postgresql.schema_incompatible"
        );
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_errors_keep_configuration_and_runtime_codes_separate() {
        let invalid = NotaryActivationFailure::from(StandaloneServerError::InvalidCelConfig(
            SENTINEL.to_string(),
        ));
        assert_eq!(invalid.code(), NotaryActivationCode::CONFIGURATION_INVALID);
        assert!(!invalid.to_string().contains(SENTINEL));

        let unavailable =
            NotaryActivationFailure::from(StandaloneServerError::CelWorkerUnavailable);
        assert_eq!(
            unavailable.code(),
            NotaryActivationCode::CEL_WORKER_UNAVAILABLE
        );
        assert!(!unavailable.to_string().contains(SENTINEL));
    }
}
