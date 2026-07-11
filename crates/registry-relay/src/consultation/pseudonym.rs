// SPDX-License-Identifier: Apache-2.0
//! Restart-only audit-pseudonym material binding for governed consultations.
//!
//! Configuration supplies only public key ids and opaque environment-source
//! references. PostgreSQL remains the sole authority for the active key id,
//! generation, binding, and write deadline. A configured staged key has no
//! authority until PostgreSQL selects it.
//!
//! Environment references are an intentionally bounded first provider. Each
//! reference must be immutable and versioned for its key id. Changing the
//! value requires a new key id because PostgreSQL deliberately persists no
//! secret-derived verifier. This module must not add a fingerprint or persist
//! the platform key-equivalence probe to compensate for mutable deployment
//! secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_audit::pseudonym_keyring::{
    AuditPseudonymCommitment, AuditPseudonymKeyId, AuditPseudonymKeyMaterial,
    TransientPseudonymInput,
};
use thiserror::Error;

use crate::config::{ConsultationConfig, MAX_AUDIT_PSEUDONYM_MATERIALS};
use crate::state_plane::{ActiveAuditPseudonymWriteEpoch, AuditPseudonymWriteAuthority};

use super::commitments::{
    ConsultationPseudonymInputs, SealedConsultationExecution, VerifiedConsentDecision,
};

/// Value-free failure taxonomy for startup loading and authority binding.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditPseudonymMaterialProviderError {
    #[error("Relay audit-pseudonym material catalog is outside its protocol bound")]
    CatalogOutOfBounds,
    #[error("Relay audit-pseudonym material catalog contains a duplicate key id")]
    DuplicateKeyId,
    #[error("Relay audit-pseudonym material catalog contains a duplicate source reference")]
    DuplicateSourceReference,
    #[error("Relay audit-pseudonym material source could not be loaded")]
    SourceLoadFailed,
    #[error("Relay audit-pseudonym key ids resolve to duplicate key material")]
    DuplicateKeyMaterial,
    #[error("Relay audit-pseudonym PostgreSQL write authority is unavailable")]
    WriteAuthorityUnavailable,
    #[error("Relay audit-pseudonym authorized key material is unavailable")]
    AuthorizedMaterialUnavailable,
}

/// Opaque startup catalog of derived audit-pseudonym material.
///
/// The provider deliberately retains neither source names nor source values.
/// It is not cloneable or serializable and exposes no raw or selector-driven
/// material lookup.
pub(crate) struct AuditPseudonymMaterialProvider {
    materials: BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>,
}

impl AuditPseudonymMaterialProvider {
    /// Load and derive every configured material exactly once at startup.
    ///
    /// Structural validation runs before any environment access. Material
    /// loading then fails closed on every platform error, and equal derived
    /// material under distinct key ids is rejected before this provider can be
    /// installed in a runtime snapshot.
    pub(crate) fn compile(
        config: &ConsultationConfig,
    ) -> Result<Self, AuditPseudonymMaterialProviderError> {
        let entries = config.audit_pseudonym_materials.entries();
        if entries.is_empty() || entries.len() > MAX_AUDIT_PSEUDONYM_MATERIALS {
            return Err(AuditPseudonymMaterialProviderError::CatalogOutOfBounds);
        }

        let mut key_ids = BTreeSet::new();
        let mut source_names = BTreeSet::new();
        for entry in entries {
            if !key_ids.insert(entry.key_id.as_str()) {
                return Err(AuditPseudonymMaterialProviderError::DuplicateKeyId);
            }
            if !source_names.insert(entry.source.environment_name().as_str()) {
                return Err(AuditPseudonymMaterialProviderError::DuplicateSourceReference);
            }
        }

        let mut materials = BTreeMap::new();
        for entry in entries {
            let material = AuditPseudonymKeyMaterial::from_env_derived(
                entry.source.environment_name().as_str(),
            )
            .map_err(|_| AuditPseudonymMaterialProviderError::SourceLoadFailed)?;
            if materials
                .values()
                .any(|known: &AuditPseudonymKeyMaterial| known.is_same_material(&material))
            {
                return Err(AuditPseudonymMaterialProviderError::DuplicateKeyMaterial);
            }
            materials.insert(entry.key_id.clone(), material);
        }
        Ok(Self { materials })
    }

    /// Bind material only to the exact current epoch issued by PostgreSQL.
    ///
    /// There is intentionally no operation accepting a caller-selected key id.
    /// The returned committer consumes this authority before it can produce an
    /// attempt bundle, while the epoch remains available for the durable CAS.
    pub(crate) fn bind_write(
        &self,
        authority: AuditPseudonymWriteAuthority,
    ) -> Result<BoundAuditPseudonymCommitter<'_>, AuditPseudonymMaterialProviderError> {
        let active_epoch = authority
            .authorize_use()
            .map_err(|_| AuditPseudonymMaterialProviderError::WriteAuthorityUnavailable)?;
        let material = self
            .materials
            .get(active_epoch.key_id())
            .ok_or(AuditPseudonymMaterialProviderError::AuthorizedMaterialUnavailable)?;
        Ok(BoundAuditPseudonymCommitter {
            material,
            active_epoch,
        })
    }
}

impl fmt::Debug for AuditPseudonymMaterialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditPseudonymMaterialProvider")
            .field("material_count", &self.materials.len())
            .field("material", &"<redacted>")
            .finish()
    }
}

/// Non-cloneable material bound to one still-consumable PostgreSQL epoch.
pub(crate) struct BoundAuditPseudonymCommitter<'provider> {
    material: &'provider AuditPseudonymKeyMaterial,
    active_epoch: ActiveAuditPseudonymWriteEpoch,
}

impl BoundAuditPseudonymCommitter<'_> {
    /// Consume typed, zeroizing inputs and compute only the four frozen Relay
    /// consultation commitment domains.
    pub(crate) fn prepare_attempt<'profile>(
        self,
        inputs: ConsultationPseudonymInputs<'profile>,
    ) -> PreparedConsultationPseudonyms<'profile> {
        let ConsultationPseudonymInputs {
            execution,
            canonical_purpose,
            consent,
            subject,
            input,
            predicate,
            consent_evidence,
        } = inputs;
        let commitments = compute_commitments(
            self.material,
            &subject,
            &input,
            &predicate,
            consent_evidence.as_ref(),
        );
        PreparedConsultationPseudonyms {
            execution,
            canonical_purpose,
            consent,
            key_id: self.active_epoch.key_id().clone(),
            subject_handle: commitments.subject_handle,
            input_commitment: commitments.input_commitment,
            predicate_commitment: commitments.predicate_commitment,
            consent_evidence_commitment: commitments.consent_evidence_commitment,
            active_epoch: self.active_epoch,
        }
    }
}

impl fmt::Debug for BoundAuditPseudonymCommitter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundAuditPseudonymCommitter(<authority-bound material>)")
    }
}

/// Exact attempt commitments and the epoch that must be consumed by the
/// pseudonym-bound durable PostgreSQL CAS.
///
/// Fields are consultation-local for the workflow integration
/// slice. There is no constructor, Clone, serde implementation, raw material,
/// or generic commitment domain.
pub(crate) struct PreparedConsultationPseudonyms<'profile> {
    pub(super) execution: SealedConsultationExecution<'profile>,
    pub(super) canonical_purpose: Box<str>,
    pub(super) consent: VerifiedConsentDecision,
    pub(super) key_id: AuditPseudonymKeyId,
    pub(super) subject_handle: AuditPseudonymCommitment,
    pub(super) input_commitment: AuditPseudonymCommitment,
    pub(super) predicate_commitment: AuditPseudonymCommitment,
    pub(super) consent_evidence_commitment: Option<AuditPseudonymCommitment>,
    pub(super) active_epoch: ActiveAuditPseudonymWriteEpoch,
}

impl PreparedConsultationPseudonyms<'_> {
    pub(super) fn profile(&self) -> &crate::source_plan::runtime_profile::CompiledRuntimeProfile {
        self.execution.profile()
    }
}

impl fmt::Debug for PreparedConsultationPseudonyms<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedConsultationPseudonyms")
            .field("key_id", &self.key_id)
            .field("commitments", &"<redacted>")
            .field("active_epoch", &"<CAS-bound authority>")
            .finish()
    }
}

struct ComputedCommitments {
    subject_handle: AuditPseudonymCommitment,
    input_commitment: AuditPseudonymCommitment,
    predicate_commitment: AuditPseudonymCommitment,
    consent_evidence_commitment: Option<AuditPseudonymCommitment>,
}

fn compute_commitments(
    material: &AuditPseudonymKeyMaterial,
    subject: &TransientPseudonymInput,
    input: &TransientPseudonymInput,
    predicate: &TransientPseudonymInput,
    consent_evidence: Option<&TransientPseudonymInput>,
) -> ComputedCommitments {
    ComputedCommitments {
        subject_handle: material.consultation_subject_commitment(subject),
        input_commitment: material.consultation_input_commitment(input),
        predicate_commitment: material.consultation_predicate_commitment(predicate),
        consent_evidence_commitment: consent_evidence
            .map(|value| material.consultation_consent_commitment(value)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use registry_platform_audit::pseudonym_keyring::TransientPseudonymInput;
    use serde_json::json;

    use super::*;

    static ENV_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct EnvironmentGuard {
        name: String,
        previous: Option<OsString>,
    }

    impl EnvironmentGuard {
        fn set(name: String, value: impl AsRef<OsStr>) -> Self {
            let previous = std::env::var_os(&name);
            std::env::set_var(&name, value);
            Self { name, previous }
        }

        fn missing(name: String) -> Self {
            let previous = std::env::var_os(&name);
            std::env::remove_var(&name);
            Self { name, previous }
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(&self.name, previous);
            } else {
                std::env::remove_var(&self.name);
            }
        }
    }

    fn unique_env_name(label: &str) -> String {
        let sequence = ENV_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        format!("REGISTRY_RELAY_PSEUDONYM_TEST_{label}_{sequence}")
    }

    fn config(entries: &[(&str, &str)]) -> ConsultationConfig {
        config_result(entries).expect("consultation config parses")
    }

    fn config_result(entries: &[(&str, &str)]) -> Result<ConsultationConfig, serde_saphyr::Error> {
        let mut yaml = String::from(
            "notary_workload:\n  audience: relay-consultation\n  client_claim_selector: azp\n  client_value: registry-notary\n  principal_id: registry-notary\nstate_plane:\n  database_url_env: REGISTRY_RELAY_STATE_DATABASE_URL\n  chain_key_epoch_id: chain-epoch-1\n  serving_fence_lock_key: 7221091441\n  audit_pseudonym_keyring_lock_key: 7221091442\naudit_pseudonym_materials:\n",
        );
        for (key_id, source_name) in entries {
            writeln!(
                yaml,
                "  - key_id: \"{key_id}\"\n    source:\n      provider: environment\n      name: \"{source_name}\""
            )
            .expect("write test config");
        }
        serde_saphyr::from_str(&yaml)
    }

    fn input(value: serde_json::Value) -> TransientPseudonymInput {
        TransientPseudonymInput::from_jcs_value(value).expect("valid transient input")
    }

    #[test]
    fn provider_repeats_catalog_bounds_and_uniqueness_before_loading() {
        assert_eq!(
            AuditPseudonymMaterialProvider::compile(&config(&[])).unwrap_err(),
            AuditPseudonymMaterialProviderError::CatalogOutOfBounds
        );

        let key_ids = (0..33)
            .map(|index| (format!("epoch-{index}"), unique_env_name("BOUND")))
            .collect::<Vec<_>>();
        let entries = key_ids
            .iter()
            .map(|(key_id, source)| (key_id.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            AuditPseudonymMaterialProvider::compile(&config(&entries)).unwrap_err(),
            AuditPseudonymMaterialProviderError::CatalogOutOfBounds
        );

        let source_a = unique_env_name("DUPLICATE_ID_A");
        let source_b = unique_env_name("DUPLICATE_ID_B");
        assert_eq!(
            AuditPseudonymMaterialProvider::compile(&config(&[
                ("epoch-duplicate", &source_a),
                ("epoch-duplicate", &source_b),
            ]))
            .unwrap_err(),
            AuditPseudonymMaterialProviderError::DuplicateKeyId
        );

        let source = unique_env_name("DUPLICATE_SOURCE");
        assert_eq!(
            AuditPseudonymMaterialProvider::compile(&config(&[
                ("epoch-source-a", &source),
                ("epoch-source-b", &source),
            ]))
            .unwrap_err(),
            AuditPseudonymMaterialProviderError::DuplicateSourceReference
        );
    }

    #[test]
    fn provider_rejects_missing_empty_weak_and_oversized_values_without_leaks() {
        let oversized_marker = "large-value-must-not-leak";
        let oversized = format!(
            "{oversized_marker}{}",
            "x".repeat(4097 - oversized_marker.len())
        );
        let cases = [
            ("MISSING", None),
            ("EMPTY", Some(String::new())),
            ("WEAK", Some("weak-value-must-not-leak-123456".to_owned())),
            ("OVERSIZED", Some(oversized)),
        ];
        for (label, value) in cases {
            if label == "WEAK" {
                assert_eq!(value.as_ref().expect("weak value").len(), 31);
            } else if label == "OVERSIZED" {
                assert_eq!(value.as_ref().expect("oversized value").len(), 4097);
            }
            let source = unique_env_name(label);
            let guard = match value {
                Some(value) => EnvironmentGuard::set(source.clone(), value),
                None => EnvironmentGuard::missing(source.clone()),
            };
            let error = AuditPseudonymMaterialProvider::compile(&config(&[("epoch-a", &source)]))
                .expect_err("invalid source must fail closed");
            assert_eq!(error, AuditPseudonymMaterialProviderError::SourceLoadFailed);
            let diagnostics = format!("{error:?} {error}");
            assert!(!diagnostics.contains(&source));
            assert!(!diagnostics.contains("weak-value-must-not-leak"));
            assert!(!diagnostics.contains("large-value-must-not-leak"));
            drop(guard);
        }
    }

    #[cfg(unix)]
    #[test]
    fn provider_rejects_non_unicode_environment_material_without_leaks() {
        let source = unique_env_name("NON_UNICODE");
        let marker = OsString::from_vec(vec![0xff; 32]);
        let _guard = EnvironmentGuard::set(source.clone(), marker);
        let error = AuditPseudonymMaterialProvider::compile(&config(&[("epoch-a", &source)]))
            .expect_err("non-Unicode source must fail closed");
        assert_eq!(error, AuditPseudonymMaterialProviderError::SourceLoadFailed);
        assert!(!format!("{error:?} {error}").contains(&source));
    }

    #[test]
    fn config_environment_name_grammar_matches_the_platform_constructor() {
        let max_name = "A".repeat(128);
        for name in ["A", "_A1", max_name.as_str()] {
            let _guard = EnvironmentGuard::set(name.to_owned(), "G".repeat(32));
            assert!(config_result(&[("epoch-a", name)]).is_ok());
            assert!(AuditPseudonymKeyMaterial::from_env_derived(name).is_ok());
        }

        let over_bound = "A".repeat(129);
        for name in [
            "",
            "1LEADING",
            "-LEADING",
            "HAS-DASH",
            "HAS SPACE",
            "NON_ASCII_é",
            over_bound.as_str(),
        ] {
            assert!(config_result(&[("epoch-a", name)]).is_err());
            assert!(matches!(
                AuditPseudonymKeyMaterial::from_env_derived(name),
                Err(
                    registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyringError::InvalidEnvironmentVariableName
                )
            ));
        }
    }

    #[test]
    fn provider_loads_exact_environment_value_without_trimming() {
        let source = unique_env_name("NO_TRIM");
        let exact = format!("{}\n", "x".repeat(31));
        assert_eq!(exact.len(), 32);
        let _guard = EnvironmentGuard::set(source.clone(), &exact);
        let provider = AuditPseudonymMaterialProvider::compile(&config(&[("epoch-a", &source)]))
            .expect("31 bytes plus newline is an exact strong source value");
        assert_eq!(provider.materials.len(), 1);
    }

    #[test]
    fn provider_rejects_duplicate_derived_material() {
        let source_a = unique_env_name("DUPLICATE_MATERIAL_A");
        let source_b = unique_env_name("DUPLICATE_MATERIAL_B");
        let _guard_a = EnvironmentGuard::set(source_a.clone(), "U".repeat(32));
        let _guard_b = EnvironmentGuard::set(source_b.clone(), "U".repeat(32));
        assert_eq!(
            AuditPseudonymMaterialProvider::compile(&config(&[
                ("epoch-a", &source_a),
                ("epoch-b", &source_b),
            ]))
            .unwrap_err(),
            AuditPseudonymMaterialProviderError::DuplicateKeyMaterial
        );
    }

    #[test]
    fn provider_debug_retains_no_source_or_secret_value() {
        let source = unique_env_name("SOURCE_NAME_MUST_NOT_LEAK");
        let secret = "provider-secret-marker-must-not-leak-32";
        let _guard = EnvironmentGuard::set(source.clone(), secret);
        let consultation = config(&[("epoch-a", &source)]);
        let config_debug = format!("{consultation:?}");
        assert!(!config_debug.contains(&source));

        let provider =
            AuditPseudonymMaterialProvider::compile(&consultation).expect("strong source loads");
        let provider_debug = format!("{provider:?}");
        assert!(!provider_debug.contains(&source));
        assert!(!provider_debug.contains(secret));
        assert!(provider_debug.contains("material_count"));
    }

    #[test]
    fn authorized_selection_is_exact_and_absent_id_fails_closed() {
        let active_source = unique_env_name("ACTIVE");
        let staged_source = unique_env_name("STAGED");
        let _active_guard = EnvironmentGuard::set(active_source.clone(), "B".repeat(32));
        let _staged_guard = EnvironmentGuard::set(staged_source.clone(), "C".repeat(32));
        let provider = AuditPseudonymMaterialProvider::compile(&config(&[
            ("epoch-active", &active_source),
            ("epoch-staged", &staged_source),
        ]))
        .expect("both sources load as inert material");

        let active = AuditPseudonymKeyId::parse("epoch-active").expect("valid key id");
        let staged = AuditPseudonymKeyId::parse("epoch-staged").expect("valid key id");
        let missing = AuditPseudonymKeyId::parse("epoch-missing").expect("valid key id");
        let subject = input(json!({"subject": "same"}));
        let active_commitment = provider
            .materials
            .get(&active)
            .expect("configured active material")
            .consultation_subject_commitment(&subject);
        let staged_commitment = provider
            .materials
            .get(&staged)
            .expect("configured staged material")
            .consultation_subject_commitment(&subject);
        assert_ne!(active_commitment, staged_commitment);
        assert!(!provider.materials.contains_key(&missing));
        assert_eq!(provider.materials.len(), 2);
    }

    #[test]
    fn provider_maps_only_the_four_pinned_consultation_commitments() {
        const EXPECTED: [&str; 4] = [
            "hmac-sha256:80d4a9f979be7df1455203f542a3c393c995aeca508a3009cdbd7e37c45021da",
            "hmac-sha256:432d0c8e572abd017f848b4e74be7fbb9c9da015a54c3ef47458f0fabe147021",
            "hmac-sha256:614cfadc2079ff97728a5007908f6c53447f087a22d084eaefb80c5a682fbba6",
            "hmac-sha256:25483260fc7fa92958c120142cbde1a4a071fc62f3f02ac32ff2e216741e5d6b",
        ];

        let source = unique_env_name("PINNED");
        let _guard = EnvironmentGuard::set(source.clone(), "B".repeat(32));
        let provider = AuditPseudonymMaterialProvider::compile(&config(&[("epoch-a", &source)]))
            .expect("pinned source loads");
        let key_id = AuditPseudonymKeyId::parse("epoch-a").expect("valid key id");
        let material = provider
            .materials
            .get(&key_id)
            .expect("configured material");
        let subject = input(json!({
            "tenant": "example-government",
            "registry_instance": "people-primary",
            "identifier_type": "national_id",
            "canonical_subject": "123456789",
        }));
        let input_value = input(json!({
            "profile_id": "example.person-status.exact",
            "profile_version": "1",
            "canonical_inputs": {"subject_id": "123456789"},
        }));
        let predicate = input(json!({
            "binding_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "source_operation": "person.lookup-exact",
            "exact_predicate": {"national_id": "123456789"},
        }));
        let consent = input(json!({
            "verifier_id": "government-consent-service",
            "raw_consent_reference": "consent-abc-123",
        }));
        let commitments =
            compute_commitments(material, &subject, &input_value, &predicate, Some(&consent));
        assert_eq!(commitments.subject_handle.as_str(), EXPECTED[0]);
        assert_eq!(commitments.input_commitment.as_str(), EXPECTED[1]);
        assert_eq!(commitments.predicate_commitment.as_str(), EXPECTED[2]);
        assert_eq!(
            commitments
                .consent_evidence_commitment
                .as_ref()
                .expect("consent commitment")
                .as_str(),
            EXPECTED[3]
        );

        let no_consent = compute_commitments(material, &subject, &input_value, &predicate, None);
        assert!(no_consent.consent_evidence_commitment.is_none());
    }
}
