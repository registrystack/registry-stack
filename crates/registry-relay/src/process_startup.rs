// SPDX-License-Identifier: Apache-2.0
//! Stable, value-free operator diagnostics for the Relay process boundary.
//!
//! Startup source errors can contain local paths, parser excerpts, URLs,
//! identities, hashes, and supplied values. They must be classified before
//! crossing the default stderr or tracing boundary. The private representation
//! prevents callers from constructing unreviewed codes, while [`ProcessStartupCode::ALL`]
//! and [`PROCESS_STARTUP_CODE_DEFINITIONS`] expose the complete catalog for
//! generated references and release checks.

use std::fmt::{self, Display};

use registry_platform_ops::BundleVerificationCode;
use serde::Serialize;

/// One reviewed Relay process-boundary failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessStartupCode(ProcessStartupCodeValue);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum ProcessStartupCodeValue {
    BundleBindingRejected,
    BundleRollbackRejected,
    BundleSignatureRejected,
    BundleValidationRejected,
    ConfigDocumentInvalid,
    ConfigSourceUnavailable,
    ConfigValidationRejected,
    ConsultationArtifactsRejected,
    DoctorFailed,
    ListenerUnavailable,
    RuntimeInitializationFailed,
}

impl ProcessStartupCode {
    pub const BUNDLE_BINDING_REJECTED: Self = Self(ProcessStartupCodeValue::BundleBindingRejected);
    pub const BUNDLE_ROLLBACK_REJECTED: Self =
        Self(ProcessStartupCodeValue::BundleRollbackRejected);
    pub const BUNDLE_SIGNATURE_REJECTED: Self =
        Self(ProcessStartupCodeValue::BundleSignatureRejected);
    pub const BUNDLE_VALIDATION_REJECTED: Self =
        Self(ProcessStartupCodeValue::BundleValidationRejected);
    pub const CONFIG_DOCUMENT_INVALID: Self = Self(ProcessStartupCodeValue::ConfigDocumentInvalid);
    pub const CONFIG_SOURCE_UNAVAILABLE: Self =
        Self(ProcessStartupCodeValue::ConfigSourceUnavailable);
    pub const CONFIG_VALIDATION_REJECTED: Self =
        Self(ProcessStartupCodeValue::ConfigValidationRejected);
    pub const CONSULTATION_ARTIFACTS_REJECTED: Self =
        Self(ProcessStartupCodeValue::ConsultationArtifactsRejected);
    pub const DOCTOR_FAILED: Self = Self(ProcessStartupCodeValue::DoctorFailed);
    pub const LISTENER_UNAVAILABLE: Self = Self(ProcessStartupCodeValue::ListenerUnavailable);
    pub const RUNTIME_INITIALIZATION_FAILED: Self =
        Self(ProcessStartupCodeValue::RuntimeInitializationFailed);

    /// Every published Relay process-boundary code in stable string order.
    pub const ALL: &'static [Self] = &[
        Self::BUNDLE_BINDING_REJECTED,
        Self::BUNDLE_ROLLBACK_REJECTED,
        Self::BUNDLE_SIGNATURE_REJECTED,
        Self::BUNDLE_VALIDATION_REJECTED,
        Self::CONFIG_DOCUMENT_INVALID,
        Self::CONFIG_SOURCE_UNAVAILABLE,
        Self::CONFIG_VALIDATION_REJECTED,
        Self::CONSULTATION_ARTIFACTS_REJECTED,
        Self::DOCTOR_FAILED,
        Self::LISTENER_UNAVAILABLE,
        Self::RUNTIME_INITIALIZATION_FAILED,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            ProcessStartupCodeValue::BundleBindingRejected => {
                "relay.startup.bundle_binding_rejected"
            }
            ProcessStartupCodeValue::BundleRollbackRejected => {
                "relay.startup.bundle_rollback_rejected"
            }
            ProcessStartupCodeValue::BundleSignatureRejected => {
                "relay.startup.bundle_signature_rejected"
            }
            ProcessStartupCodeValue::BundleValidationRejected => {
                "relay.startup.bundle_validation_rejected"
            }
            ProcessStartupCodeValue::ConfigDocumentInvalid => {
                "relay.startup.config_document_invalid"
            }
            ProcessStartupCodeValue::ConfigSourceUnavailable => {
                "relay.startup.config_source_unavailable"
            }
            ProcessStartupCodeValue::ConfigValidationRejected => {
                "relay.startup.config_validation_rejected"
            }
            ProcessStartupCodeValue::ConsultationArtifactsRejected => {
                "relay.startup.consultation_artifacts_rejected"
            }
            ProcessStartupCodeValue::DoctorFailed => "relay.startup.doctor_failed",
            ProcessStartupCodeValue::ListenerUnavailable => "relay.startup.listener_unavailable",
            ProcessStartupCodeValue::RuntimeInitializationFailed => {
                "relay.startup.runtime_initialization_failed"
            }
        }
    }

    #[must_use]
    pub fn definition(self) -> &'static ProcessStartupCodeDefinition {
        let index = match self.0 {
            ProcessStartupCodeValue::BundleBindingRejected => 0,
            ProcessStartupCodeValue::BundleRollbackRejected => 1,
            ProcessStartupCodeValue::BundleSignatureRejected => 2,
            ProcessStartupCodeValue::BundleValidationRejected => 3,
            ProcessStartupCodeValue::ConfigDocumentInvalid => 4,
            ProcessStartupCodeValue::ConfigSourceUnavailable => 5,
            ProcessStartupCodeValue::ConfigValidationRejected => 6,
            ProcessStartupCodeValue::ConsultationArtifactsRejected => 7,
            ProcessStartupCodeValue::DoctorFailed => 8,
            ProcessStartupCodeValue::ListenerUnavailable => 9,
            ProcessStartupCodeValue::RuntimeInitializationFailed => 10,
        };
        &PROCESS_STARTUP_CODE_DEFINITIONS[index]
    }

    /// Project a shared bundle-verification category into the Relay process
    /// namespace without carrying its source error payload.
    #[must_use]
    pub fn from_bundle_verification(code: BundleVerificationCode) -> Self {
        if code == BundleVerificationCode::REJECTED_BINDING {
            Self::BUNDLE_BINDING_REJECTED
        } else if code == BundleVerificationCode::REJECTED_ROLLBACK {
            Self::BUNDLE_ROLLBACK_REJECTED
        } else if code == BundleVerificationCode::REJECTED_SIGNATURE {
            Self::BUNDLE_SIGNATURE_REJECTED
        } else if code == BundleVerificationCode::REJECTED_VALIDATION {
            Self::BUNDLE_VALIDATION_REJECTED
        } else {
            panic!("unmapped shared bundle-verification code")
        }
    }
}

impl Display for ProcessStartupCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProcessStartupCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Publication lifecycle for one Relay process-boundary code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStartupCodeLifecycle {
    Unreleased,
    Active,
    Deprecated,
}

/// Restriction applied to process-boundary evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStartupEvidencePolicy {
    /// Publish only catalog-owned code and static guidance.
    NoRuntimeValues,
}

/// Reviewed, value-free operator guidance for one process-boundary code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessStartupCodeDefinition {
    pub code: ProcessStartupCode,
    pub phase: &'static str,
    pub safe_meaning: &'static str,
    pub rule: &'static str,
    pub safe_remediation: &'static str,
    pub evidence_scope: &'static str,
    pub evidence_policy: ProcessStartupEvidencePolicy,
    pub evidence_limitation: &'static str,
    pub docs_slug: &'static str,
    pub lifecycle: ProcessStartupCodeLifecycle,
    pub introduced_in: Option<&'static str>,
}

impl ProcessStartupCodeDefinition {
    #[must_use]
    pub fn lifecycle_metadata_is_valid(&self) -> bool {
        match self.lifecycle {
            ProcessStartupCodeLifecycle::Unreleased => self.introduced_in.is_none(),
            ProcessStartupCodeLifecycle::Active | ProcessStartupCodeLifecycle::Deprecated => {
                self.introduced_in.is_some_and(is_numeric_release_version)
            }
        }
    }
}

fn is_numeric_release_version(version: &str) -> bool {
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}

/// Complete product-owned Relay process-boundary catalog.
pub const PROCESS_STARTUP_CODE_DEFINITIONS: &[ProcessStartupCodeDefinition] = &[
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::BUNDLE_BINDING_REJECTED,
        phase: "bundle_verification",
        safe_meaning: "The governed bundle does not match this Relay runtime target.",
        rule: "registry.relay.startup.bundle_binding_matches_runtime",
        safe_remediation: "Use a governed bundle issued for this Relay runtime target.",
        evidence_scope: "governed bundle and Relay runtime binding",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose configured or received binding values.",
        docs_slug: "bundle-binding-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::BUNDLE_ROLLBACK_REJECTED,
        phase: "bundle_activation",
        safe_meaning: "The governed bundle or override failed Relay anti-rollback checks.",
        rule: "registry.relay.startup.bundle_antirollback_satisfied",
        safe_remediation: "Use a monotonic governed bundle or an authorized break-glass selection.",
        evidence_scope: "local anti-rollback state and governed bundle or override metadata",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose sequences, hashes, paths, operators, or approval values.",
        docs_slug: "bundle-rollback-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::BUNDLE_SIGNATURE_REJECTED,
        phase: "bundle_verification",
        safe_meaning: "The governed bundle failed authenticity or content-integrity verification.",
        rule: "registry.relay.startup.bundle_authenticity_and_integrity_accepted",
        safe_remediation: "Rebuild and sign the complete bundle with an accepted trust configuration.",
        evidence_scope: "bundle trust metadata, signature envelope, file closure, and content digests",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose signer identifiers, file names, hashes, or trust-anchor values.",
        docs_slug: "bundle-signature-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::BUNDLE_VALIDATION_REJECTED,
        phase: "bundle_verification",
        safe_meaning: "The governed bundle or local acceptance metadata is invalid.",
        rule: "registry.relay.startup.bundle_inputs_are_valid",
        safe_remediation: "Regenerate the bundle and acceptance metadata using supported formats.",
        evidence_scope: "bundle encoding, manifest, acceptance metadata, and required local inputs",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose parser excerpts, local paths, hashes, identities, or supplied values.",
        docs_slug: "bundle-validation-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::CONFIG_DOCUMENT_INVALID,
        phase: "config_loading",
        safe_meaning: "The Relay configuration document could not be parsed.",
        rule: "registry.relay.startup.config_document_parses",
        safe_remediation: "Check the configuration encoding, syntax, fields, and environment expressions.",
        evidence_scope: "Relay configuration encoding, syntax, field grammar, and environment expressions",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose parser excerpts, environment names, local paths, or supplied values.",
        docs_slug: "config-document-invalid",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::CONFIG_SOURCE_UNAVAILABLE,
        phase: "config_loading",
        safe_meaning: "The Relay configuration source could not be read.",
        rule: "registry.relay.startup.config_source_is_readable",
        safe_remediation: "Check that the configured source exists and is readable by the Relay process.",
        evidence_scope: "Relay configuration and metadata sources",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose local paths, operating-system errors, or source contents.",
        docs_slug: "config-source-unavailable",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::CONFIG_VALIDATION_REJECTED,
        phase: "config_validation",
        safe_meaning: "The parsed Relay configuration failed product validation.",
        rule: "registry.relay.startup.config_product_invariants_hold",
        safe_remediation: "Correct the configuration and its governed runtime bindings, then retry.",
        evidence_scope: "parsed Relay configuration and governed runtime bindings",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose configured identifiers, URLs, environment names, hashes, or source values.",
        docs_slug: "config-validation-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::CONSULTATION_ARTIFACTS_REJECTED,
        phase: "consultation_activation",
        safe_meaning: "The governed consultation artifact closure failed startup validation.",
        rule: "registry.relay.startup.consultation_artifact_closure_is_valid",
        safe_remediation: "Rebuild the complete hash-covered consultation artifact closure and retry.",
        evidence_scope: "governed consultation artifact closure and runtime bindings",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose artifact paths, hashes, selectors, identities, or parser excerpts.",
        docs_slug: "consultation-artifacts-rejected",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::DOCTOR_FAILED,
        phase: "operator_diagnostics",
        safe_meaning: "Relay doctor found one or more blocking diagnostics.",
        rule: "registry.relay.startup.doctor_has_no_blocking_diagnostics",
        safe_remediation: "Use the static diagnostic codes and actions in the doctor report.",
        evidence_scope: "offline Relay readiness and deployment diagnostics",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The process failure does not repeat diagnostic source values or report internals.",
        docs_slug: "doctor-failed",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::LISTENER_UNAVAILABLE,
        phase: "listener_binding",
        safe_meaning: "A configured Relay listener could not be opened.",
        rule: "registry.relay.startup.listener_is_available",
        safe_remediation: "Check listener availability and process permissions, then retry.",
        evidence_scope: "configured Relay data-plane and administration listeners",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose addresses, ports, or operating-system errors.",
        docs_slug: "listener-unavailable",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
    ProcessStartupCodeDefinition {
        code: ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED,
        phase: "runtime_initialization",
        safe_meaning: "Relay runtime initialization failed.",
        rule: "registry.relay.startup.runtime_initializes",
        safe_remediation: "Review preceding static diagnostic codes, correct the runtime inputs, and retry.",
        evidence_scope: "Relay runtime dependencies and protected startup capabilities",
        evidence_policy: ProcessStartupEvidencePolicy::NoRuntimeValues,
        evidence_limitation: "The category does not disclose inner errors, paths, URLs, identities, hashes, or supplied values.",
        docs_slug: "runtime-initialization-failed",
        lifecycle: ProcessStartupCodeLifecycle::Unreleased,
        introduced_in: None,
    },
];

/// Error carrier whose rendered form contains catalog-owned static text only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessStartupFailure {
    code: ProcessStartupCode,
}

impl ProcessStartupFailure {
    #[must_use]
    pub const fn new(code: ProcessStartupCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> ProcessStartupCode {
        self.code
    }
}

impl Display for ProcessStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let definition = self.code.definition();
        write!(
            formatter,
            "{}: {} Next action: {}",
            definition.code, definition.safe_meaning, definition.safe_remediation
        )
    }
}

impl std::error::Error for ProcessStartupFailure {}

/// Emit one value-free process-boundary diagnostic.
pub fn emit_process_startup_failure(code: ProcessStartupCode) {
    let definition = code.definition();
    tracing::error!(
        code = definition.code.as_str(),
        meaning = definition.safe_meaning,
        remediation = definition.safe_remediation,
        "registry-relay process boundary rejected the operation"
    );
}
