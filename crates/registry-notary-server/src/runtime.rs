// SPDX-License-Identifier: Apache-2.0
//! Registry Notary evaluation runtime.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "registry-notary-cel")]
use crosswalk_core::{
    ErrorSeverity, MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneExpressionInput,
};
use registry_notary_core::{
    detect_dependency_cycle, missing_context_error, parse_source_lookup_reference, AccessMode,
    BatchClaimResultView, BatchEvaluateRequest, BatchEvaluateResponse, BatchItemError,
    BatchItemResponse, BatchItemStatus, BatchStatus, BatchSummary, BoundedClaimId,
    BoundedCorrelationId, BulkMode, CelBindingsConfig, ClaimDefinition, ClaimProvenance, ClaimRef,
    ClaimResultView, CredentialProfileConfig, DisclosureDowngrade, DisclosureProfile,
    EvaluateRequest, EvidenceAuthorizationDetails, EvidenceConfig, EvidenceEntity,
    EvidenceEntityRef, EvidenceError, EvidenceFormat, EvidencePrincipal, EvidenceRequestContext,
    MatchingMetadata, ProvenanceUsed, RegistryNotaryCelConfig, RenderRequest, RuleConfig,
    SelfAttestationConfig, SelfAttestationDenialCode, SourceBindingConfig, SourceCapability,
    SourceLookupReference, SourceRuntimeSummary, StoredSelfAttestationMetadata, SubjectRequest,
    TargetRefView, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP,
    SD_JWT_VC_SIGNING_ALG,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_pdp::{
    decide as pdp_decide, known_stable_code, rule_ids_by_gate as pdp_rule_ids_by_gate,
    Decision as PdpDecision, DecisionAudit as PdpDecisionAudit,
    EvidenceRequestContext as PdpRequestContext, PolicyInput as PdpPolicyInput,
    RelationshipPurposeConstraint as PdpRelationshipPurposeConstraint,
};
#[cfg(feature = "registry-notary-cel")]
use serde_json::Map;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

const SD_JWT_VC_RSA_ISSUER_KEY_TYPE: &str = "RSA";
const SD_JWT_VC_P256_ISSUER_KEY_TYPE: &str = "EC/P-256";
use tokio::task::JoinSet;
use ulid::Ulid;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::{cel_expression_uses_regex, CelWorker, CelWorkerError};
use crate::digest::hex_encode;
use crate::json_path::get_json_path;
use crate::problem::evidence_title;
use crate::request_context::with_request_correlation_id;
use crate::self_attestation_rate_limit::SelfAttestationRateLimitKeys;

#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_CLAIM_BINDINGS: usize = 64;
#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_VAR_BINDINGS: usize = 64;

mod access;
mod catalog;
mod cel;
mod disclosure;
mod evaluation;
mod matching;
mod memo;
mod render;
mod source_loading;
mod source_reader;
mod store;
mod types;

use access::*;
pub use catalog::*;
#[cfg(feature = "registry-notary-cel")]
pub(crate) use cel::validate_cel_claims_for_startup;
use disclosure::*;
pub use evaluation::*;
pub(crate) use matching::*;
pub use memo::*;
pub use render::*;
use source_loading::*;
pub use source_reader::*;
pub use store::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::cel::*;
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_notary_core::Hashed;
    use registry_notary_core::SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR;

    #[derive(Debug, Default)]
    struct CountingSource {
        read_count: AtomicU64,
        purposes: Mutex<Vec<String>>,
    }

    impl SourceReader for CountingSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                self.purposes
                    .lock()
                    .expect("purposes mutex is not poisoned")
                    .push(purpose.to_string());
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    /// Returns a `value` field of the wrong JSON shape (a string) so tests
    /// can exercise `validate_claim_value_type` refusing an extract result
    /// that does not conform to the claim's declared `value.type`.
    #[derive(Debug, Default)]
    struct WrongTypeSource;

    impl SourceReader for WrongTypeSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": "not-a-boolean",
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct DependentLookupSource {
        first_row: Value,
        reads: Mutex<Vec<(String, Value)>>,
    }

    impl DependentLookupSource {
        fn new(first_row: Value) -> Self {
            Self {
                first_row,
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    impl SourceReader for DependentLookupSource {
        fn read_one<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let context = EvidenceRequestContext {
                    requester: None,
                    target: EvidenceEntity::from_subject_request("Person", subject.clone()),
                    relationship: None,
                    on_behalf_of: None,
                };
                self.read_one_for_context(binding, &context, purpose).await
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let lookup_value = context
                    .lookup_value(&binding.lookup.input)
                    .ok_or_else(|| missing_context_error(&binding.lookup.input))?;
                self.reads
                    .lock()
                    .expect("reads mutex is not poisoned")
                    .push((binding.entity.clone(), lookup_value.clone()));
                match binding.entity.as_str() {
                    "civil_status_record" => Ok(self.first_row.clone()),
                    "birth_event" => Ok(json!({
                        "id": lookup_value,
                        "certificate_id": "certificate-456",
                        "value": true,
                    })),
                    _ => Err(EvidenceError::SourceNotFound),
                }
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct RuntimeSummarySource {
        inner: CountingSource,
    }

    impl SourceReader for RuntimeSummarySource {
        fn observed_source_runtimes<'a>(
            &'a self,
            _evidence: &'a EvidenceConfig,
            claim_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<SourceRuntimeSummary>> + Send + 'a>> {
            Box::pin(async move {
                if claim_id != "dependency" {
                    return Vec::new();
                }
                vec![SourceRuntimeSummary {
                    kind: SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR.to_string(),
                    config_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    assurance: registry_notary_core::SourceRuntimeAssurance {
                        pinned: true,
                        expression_hashes_verified: true,
                        runtime_verified: true,
                        smoke_verified: true,
                    },
                }]
            })
        }

        fn read_one<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            self.inner.read_one(binding, subject, purpose)
        }

        fn required_scopes(
            &self,
            evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            self.inner.required_scopes(evidence, claim_id)
        }
    }

    #[derive(Debug, Default)]
    struct VersionScopedSource {
        read_count: AtomicU64,
    }

    impl SourceReader for VersionScopedSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{claim_id}:1.0")])
        }

        fn required_scopes_for_claim(
            &self,
            _evidence: &EvidenceConfig,
            claim: &ClaimDefinition,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{}:{}", claim.id, claim.version)])
        }
    }

    #[derive(Debug, Default)]
    struct BulkInvalidThenDirectSource {
        bulk_count: AtomicU64,
        direct_count: AtomicU64,
    }

    impl SourceReader for BulkInvalidThenDirectSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.direct_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let subject = context
                    .target_subject()
                    .ok_or(EvidenceError::TargetAttributesInsufficient)?;
                self.read_one(binding, &subject, purpose).await
            })
        }

        fn read_many_context<'a>(
            &'a self,
            bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
            Box::pin(async move {
                self.bulk_count.fetch_add(1, Ordering::SeqCst);
                bindings
                    .into_iter()
                    .map(|(_, context)| {
                        let id = context
                            .target_subject()
                            .map(|subject| subject.id)
                            .unwrap_or_default();
                        Ok(json!({ "id": id }))
                    })
                    .collect()
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct BulkStaleFreshnessSource {
        stale_observed_at: OffsetDateTime,
        bulk_count: AtomicU64,
        direct_count: AtomicU64,
        preflight_count: AtomicU64,
    }

    impl BulkStaleFreshnessSource {
        fn new() -> Self {
            Self {
                stale_observed_at: OffsetDateTime::now_utc() - time::Duration::seconds(61),
                bulk_count: AtomicU64::new(0),
                direct_count: AtomicU64::new(0),
                preflight_count: AtomicU64::new(0),
            }
        }

        fn stale_observed_at_value(&self) -> Value {
            json!(self
                .stale_observed_at
                .format(&Rfc3339)
                .expect("stale observed_at formats"))
        }
    }

    impl SourceReader for BulkStaleFreshnessSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.direct_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                    "observed_at": self.stale_observed_at_value(),
                }))
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let subject = context
                    .target_subject()
                    .ok_or(EvidenceError::TargetAttributesInsufficient)?;
                self.read_one(binding, &subject, purpose).await
            })
        }

        fn source_observed_at_for_context<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _context: &'a EvidenceRequestContext,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.preflight_count.fetch_add(1, Ordering::SeqCst);
                Ok(Some(self.stale_observed_at))
            })
        }

        fn read_many_context<'a>(
            &'a self,
            bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
            Box::pin(async move {
                self.bulk_count.fetch_add(1, Ordering::SeqCst);
                bindings
                    .into_iter()
                    .map(|(_, context)| {
                        let id = context
                            .target_subject()
                            .map(|subject| subject.id)
                            .unwrap_or_default();
                        Ok(json!({
                            "id": id,
                            "value": true,
                            "observed_at": self.stale_observed_at_value(),
                        }))
                    })
                    .collect()
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    fn test_source_binding() -> SourceBindingConfig {
        SourceBindingConfig {
            connector: registry_notary_core::SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "people".to_string(),
            entity: "person".to_string(),
            lookup: registry_notary_core::SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::from([(
                "value".to_string(),
                registry_notary_core::SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("boolean".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
            matching: registry_notary_core::SourceMatchingConfig::default(),
        }
    }

    fn dependent_source_binding(
        entity: &str,
        lookup_input: &str,
        lookup_field: &str,
    ) -> SourceBindingConfig {
        let mut binding = test_source_binding();
        binding.entity = entity.to_string();
        binding.lookup.input = lookup_input.to_string();
        binding.lookup.field = lookup_field.to_string();
        binding.fields.clear();
        binding.matching.allowed_purposes = vec!["test".to_string()];
        binding.matching.allowed_target_inputs = vec!["target.id".to_string()];
        binding
    }

    fn machine_capability(scopes: &[&str]) -> SourceCapability {
        SourceCapability::Machine {
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    fn test_purpose_constraints(purpose: &str) -> Vec<Vec<String>> {
        vec![vec![purpose.to_string()]]
    }

    fn expect_pdp_denial(
        result: Result<BindingPolicyEffect, EvidenceError>,
        expected_code: &'static str,
    ) {
        let error = result.expect_err("PDP must deny");
        let EvidenceError::PolicyDenied {
            code,
            policy_id,
            policy_hash,
            evaluated_rule_ids,
        } = error
        else {
            panic!("expected PolicyDenied, got {error:?}");
        };
        assert_eq!(code, expected_code);
        assert!(policy_id.is_some(), "PDP denial must carry policy id");
        assert!(policy_hash.is_some(), "PDP denial must carry policy hash");
        assert!(
            !evaluated_rule_ids.is_empty(),
            "PDP denial must carry evaluated rule ids"
        );
    }

    fn expect_pdp_permit(
        result: Result<BindingPolicyEffect, EvidenceError>,
    ) -> BindingPolicyEffect {
        result.expect("PDP must permit")
    }

    fn assert_collapsed_matching_error(error: EvidenceError, expected_audit_code: &'static str) {
        assert_eq!(error.code(), "evidence.not_available");
        assert_eq!(error.audit_code(), expected_audit_code);
        assert!(
            matches!(
                &error,
                EvidenceError::MatchingEvidenceNotAvailable { audit_code }
                    if *audit_code == expected_audit_code
            ),
            "expected collapsed matching error with audit code {expected_audit_code}, got {error:?}"
        );
    }

    fn matching_gate_rule_ids(extra_gates: &[&str], redacted: bool) -> Vec<String> {
        let mut rule_ids = vec![registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[0]];
        if extra_gates
            .iter()
            .any(|gate| matches!(*gate, "pdp.purpose" | "pdp.jurisdiction"))
        {
            rule_ids.push(registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[1]);
        }
        rule_ids.extend_from_slice(extra_gates);
        rule_ids.extend_from_slice(&registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[2..]);
        if redacted {
            rule_ids.push("redaction");
        }
        rule_ids
            .into_iter()
            .map(|rule_id| {
                format!(
                    "source-binding-policy:person.{}",
                    rule_id.strip_prefix("pdp.").unwrap_or(rule_id)
                )
            })
            .collect()
    }

    fn test_claim(id: &str, depends_on: Vec<&str>, has_source: bool) -> ClaimDefinition {
        let source_bindings = if has_source {
            BTreeMap::from([("src".to_string(), test_source_binding())])
        } else {
            BTreeMap::new()
        };
        ClaimDefinition {
            id: id.to_string(),
            title: id.to_string(),
            version: "1.0".to_string(),
            subject_type: "person".to_string(),
            value: registry_notary_core::ClaimValueConfig {
                value_type: "boolean".to_string(),
                unit: None,
            },
            semantics: None,
            inputs: Vec::new(),
            depends_on: depends_on.into_iter().map(str::to_string).collect(),
            purpose: None,
            source_bindings,
            rule: if has_source {
                RuleConfig::Extract {
                    source: "src".to_string(),
                    field: "value".to_string(),
                }
            } else {
                RuleConfig::Exists {
                    source: "src".to_string(),
                }
            },
            operations: registry_notary_core::ClaimOperationsConfig::default(),
            disclosure: registry_notary_core::DisclosureConfig {
                default: "value".to_string(),
                allowed: vec!["value".to_string(), "redacted".to_string()],
                downgrade: "redacted".to_string(),
            },
            formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
            credential_profiles: Vec::new(),
            cccev: None,
            oots: None,
        }
    }

    fn test_evidence(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
        Arc::new(EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims,
            ..EvidenceConfig::default()
        })
    }

    fn test_claim_result(
        claim_id: &str,
        value: Value,
        redaction_fields: BTreeSet<String>,
    ) -> ClaimResultInternal {
        ClaimResultInternal {
            evaluation_id: "eval-test".to_string(),
            claim_id: claim_id.to_string(),
            claim_version: "1.0".to_string(),
            subject_type: "person".to_string(),
            target: EvidenceEntity::new("Person"),
            requester: None,
            matching: None,
            value,
            redaction_fields,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            provenance: ClaimProvenance::new(
                "runtime.test".to_string(),
                "eval-test".to_string(),
                claim_id.to_string(),
                "1.0".to_string(),
                ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        }
    }

    fn bulk_source_connection() -> registry_notary_core::SourceConnectionConfig {
        registry_notary_core::SourceConnectionConfig {
            base_url: "https://source.test".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: None,
            expected_sidecar: None,
            dci: registry_notary_core::DciSourceConnectionConfig::default(),
            max_in_flight: 1,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 1_000,
        }
    }

    fn test_request(claim: &str) -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from(claim)],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        }
    }

    fn machine_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn self_attestation_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "citizen".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::SelfAttestation,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn self_attestation_capability(claim_id: &str) -> SourceCapability {
        SourceCapability::SelfAttestation {
            claim_id: Some(BoundedClaimId::new(claim_id).expect("claim id is bounded")),
            allowed_claim_ids: BTreeSet::new(),
            subject_binding_hash: Hashed::from_hash("sha256:test"),
        }
    }

    fn delegated_attestation_capability(
        keys: &SelfAttestationRateLimitKeys,
        requester_subject: &str,
        dependent_subject: &str,
    ) -> SourceCapability {
        delegated_attestation_capability_with_id_types(
            keys,
            "national_id",
            requester_subject,
            "civil_registration_id",
            dependent_subject,
        )
    }

    fn delegated_attestation_capability_with_id_types(
        keys: &SelfAttestationRateLimitKeys,
        requester_id_type: &str,
        requester_subject: &str,
        dependent_id_type: &str,
        dependent_subject: &str,
    ) -> SourceCapability {
        SourceCapability::DelegatedAttestation {
            proof_claim_id: BoundedClaimId::new("guardian-link")
                .expect("proof claim id is bounded"),
            allowed_claim_ids: BTreeSet::from([
                BoundedClaimId::new("selected").expect("delegated claim id is bounded")
            ]),
            requester_subject_binding_hash: keys
                .delegated_subject_binding(requester_id_type, requester_subject)
                .expect("requester hashes"),
            dependent_target_hash: keys
                .delegated_subject_binding(dependent_id_type, dependent_subject)
                .expect("dependent hashes"),
            relationship_type: registry_notary_core::ConfigMetadata::new("guardian")
                .expect("relationship type is bounded"),
        }
    }

    fn delegated_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "guardian".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::DelegatedAttestation,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn delegated_runtime_request() -> EvaluateRequest {
        EvaluateRequest {
            requester: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "NAT-123".to_string(),
                    id_type: Some("national_id".to_string()),
                },
            )),
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "CHILD-123".to_string(),
                    id_type: Some("civil_registration_id".to_string()),
                },
            )),
            relationship: Some(registry_notary_core::EvidenceRelationship {
                relationship_type: "guardian".to_string(),
                attributes: BTreeMap::new(),
            }),
            on_behalf_of: None,
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        }
    }

    #[test]
    fn claim_summary_advertises_cccev_evidence_type_metadata() {
        let mut claim = test_claim("civil-child-status", Vec::new(), false);
        claim.cccev = Some(registry_notary_core::CccevConfig {
            requirement_type: Some("InformationRequirement".to_string()),
            evidence_type: Some("civil_child_status_evidence".to_string()),
            evidence_type_iri: Some(
                "https://demo.example.gov/evidence-types/civil-child-status".to_string(),
            ),
        });

        let summary = claim_summary(&claim);

        assert_eq!(summary["evidence_type"], "civil_child_status_evidence");
        assert_eq!(
            summary["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
        assert_eq!(
            summary["cccev"]["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
    }

    #[test]
    fn claim_summary_advertises_safe_target_inputs_for_demographic_matching() {
        let mut claim = test_claim("birth-record-exists", Vec::new(), true);
        let binding = claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has a source binding");
        binding.connector = registry_notary_core::SourceConnectorKind::Dci;
        binding.connection = Some("opencrvs_private_connection".to_string());
        binding.dataset = "civil_registry".to_string();
        binding.entity = "birth_registration".to_string();
        binding.lookup.input = "target.attributes.given_name".to_string();
        binding.lookup.field = "childFirstNames".to_string();
        binding.query_fields = vec![
            registry_notary_core::SourceQueryFieldConfig {
                input: "target.attributes.given_name".to_string(),
                field: "childFirstNames".to_string(),
                op: "eq".to_string(),
            },
            registry_notary_core::SourceQueryFieldConfig {
                input: "target.attributes.family_name".to_string(),
                field: "childLastName".to_string(),
                op: "eq".to_string(),
            },
            registry_notary_core::SourceQueryFieldConfig {
                input: "target.attributes.birthdate".to_string(),
                field: "childDoB".to_string(),
                op: "eq".to_string(),
            },
        ];
        binding.matching.policy_id = Some("opencrvs-demographic-v1".to_string());
        binding.matching.method = Some("exact_name_birthdate".to_string());
        binding.matching.target_type = Some("Person".to_string());
        binding.matching.confidence = Some("high".to_string());
        binding.matching.sufficient_target_inputs = vec![vec![
            "target.attributes.given_name".to_string(),
            "target.attributes.family_name".to_string(),
            "target.attributes.birthdate".to_string(),
        ]];
        binding.matching.allowed_target_inputs = vec![
            "target.attributes.given_name".to_string(),
            "target.attributes.family_name".to_string(),
            "target.attributes.birthdate".to_string(),
        ];

        let summary = claim_summary(&claim);

        let target_inputs = summary["target_inputs"]
            .as_array()
            .expect("target inputs are advertised");
        assert_eq!(target_inputs.len(), 1);
        let method = &target_inputs[0];
        assert_eq!(method["policy_id"], "opencrvs-demographic-v1");
        assert_eq!(method["method"], "exact_name_birthdate");
        assert_eq!(method["target_type"], "Person");
        assert_eq!(method["confidence"], "high");
        assert_eq!(
            method["groups"][0]["inputs"],
            json!([
                {
                    "path": "target.attributes.given_name",
                    "kind": "attribute",
                    "name": "given_name",
                    "label": "Given name",
                },
                {
                    "path": "target.attributes.family_name",
                    "kind": "attribute",
                    "name": "family_name",
                    "label": "Family name",
                },
                {
                    "path": "target.attributes.birthdate",
                    "kind": "attribute",
                    "name": "birthdate",
                    "label": "Birthdate",
                }
            ])
        );
        let discovery_text = serde_json::to_string(&summary).expect("summary serializes");
        for private_detail in [
            "opencrvs_private_connection",
            "civil_registry",
            "birth_registration",
            "childFirstNames",
            "childLastName",
            "childDoB",
        ] {
            assert!(
                !discovery_text.contains(private_detail),
                "claim discovery leaked {private_detail}"
            );
        }
    }

    #[test]
    fn claim_summary_advertises_alternate_identifier_and_attribute_input_groups() {
        let mut claim = test_claim("person-is-alive", Vec::new(), true);
        let binding = claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has a source binding");
        binding.matching.policy_id = Some("civil-person-match-v1".to_string());
        binding.matching.method = Some("identifier_or_demographic".to_string());
        binding.matching.target_type = Some("Person".to_string());
        binding.matching.sufficient_target_inputs = vec![
            vec!["target.identifiers.national_id".to_string()],
            vec![
                "target.attributes.given_name".to_string(),
                "target.attributes.family_name".to_string(),
                "target.attributes.birthdate".to_string(),
            ],
        ];

        let summary = claim_summary(&claim);

        assert_eq!(
            summary["target_inputs"][0]["groups"][0]["inputs"],
            json!([
                {
                    "path": "target.identifiers.national_id",
                    "kind": "identifier",
                    "name": "national_id",
                    "label": "National id",
                }
            ])
        );
        assert_eq!(
            summary["target_inputs"][0]["groups"][1]["inputs"][0],
            json!({
                "path": "target.attributes.given_name",
                "kind": "attribute",
                "name": "given_name",
                "label": "Given name",
            })
        );
    }

    #[test]
    fn claim_summary_does_not_publish_partial_target_input_groups() {
        let mut claim = test_claim("person-is-alive", Vec::new(), true);
        let binding = claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has a source binding");
        binding.matching.policy_id = Some("mixed-unsupported-v1".to_string());
        binding.matching.sufficient_target_inputs = vec![vec![
            "target.attributes.given_name".to_string(),
            "requester.attributes.case_id".to_string(),
        ]];

        let summary = claim_summary(&claim);

        assert!(summary.get("target_inputs").is_none());
    }

    #[test]
    fn claim_summary_omits_target_inputs_without_configured_matching_policy() {
        let claim = test_claim("date-of-birth", Vec::new(), true);

        let summary = claim_summary(&claim);

        assert!(summary.get("target_inputs").is_none());
    }

    #[test]
    fn self_attestation_source_capability_uses_keyed_subject_binding_hash() {
        const ENV: &str = "TEST_RUNTIME_AUDIT_HASH_SECRET";
        std::env::set_var(ENV, "0123456789abcdef0123456789abcdef");
        let keys = SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::from_env(ENV).expect("test audit hasher loads"),
        );
        let mut principal = self_attestation_principal();
        principal.verified_claims = Some(
            serde_json::from_value(json!({
                "issuer": "https://id.example.gov",
                "audiences": ["registry-notary"],
                "subject_binding_claim": "national_id",
                "subject_binding_value": "12345678901"
            }))
            .expect("verified claims parse"),
        );

        let capability =
            source_capability_for_principal(&keys, &principal, &["selected".to_string()])
                .expect("source capability builds");
        let SourceCapability::SelfAttestation {
            subject_binding_hash,
            ..
        } = capability
        else {
            panic!("expected self-attestation capability");
        };

        assert!(subject_binding_hash.as_str().starts_with("hmac-sha256:"));
        assert!(!subject_binding_hash.as_str().contains("12345678901"));
    }

    #[test]
    fn service_document_advertises_api_key_and_bearer_auth() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);

        assert_eq!(document["auth"]["methods"], json!(["api_key", "bearer"]));
        assert_eq!(document["auth"]["api_key"]["header"], json!("X-Api-Key"));
        assert_eq!(document["auth"]["bearer"]["header"], json!("Authorization"));
        assert_eq!(document["auth"]["bearer"]["scheme"], json!("bearer"));
        assert_eq!(
            document["auth"]["bearer"]["format"],
            json!("Bearer <token>")
        );
        assert_eq!(document["auth"]["audience"], json!("evidence.test"));
    }

    #[test]
    fn service_document_advertises_sd_jwt_vc_conformance_capabilities() {
        let mut credential_profiles = BTreeMap::new();
        credential_profiles.insert(
            "profile-a".to_string(),
            CredentialProfileConfig {
                format: FORMAT_SD_JWT_VC.to_string(),
                issuer: "did:web:issuer.test".to_string(),
                signing_key: "issuer-key".to_string(),
                vct: "https://issuer.test/credentials/profile-a".to_string(),
                validity_seconds: 600,
                holder_binding: registry_notary_core::HolderBindingConfig {
                    mode: "did".to_string(),
                    proof_of_possession: Some("required".to_string()),
                    allowed_did_methods: vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()],
                },
                allowed_claims: vec!["claim-a".to_string()],
                disclosure: registry_notary_core::CredentialDisclosureConfig {
                    allowed: vec!["predicate".to_string()],
                },
            },
        );
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            credential_profiles,
            signing_keys: BTreeMap::from([(
                "issuer-key".to_string(),
                serde_json::from_value(json!({
                    "provider": "local_jwk_env",
                    "private_jwk_env": "ISSUER_KEY",
                    "alg": "ES256",
                    "kid": "did:web:issuer.test#key-1",
                    "status": "active"
                }))
                .expect("signing key parses"),
            )]),
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);
        let capabilities = &document["credential_capabilities"]["sd_jwt_vc"];

        assert_eq!(capabilities["media_type"], json!(FORMAT_SD_JWT_VC));
        assert_eq!(capabilities["jwt_typ"], json!(SD_JWT_VC_JWT_TYP));
        assert_eq!(capabilities["signing_algs"], json!(["ES256"]));
        assert_eq!(
            capabilities["issuer_key_types"],
            json!([SD_JWT_VC_P256_ISSUER_KEY_TYPE])
        );
        assert_eq!(
            capabilities["holder_binding_methods"],
            json!([SD_JWT_VC_HOLDER_BINDING_METHOD])
        );
        assert_eq!(capabilities["status_methods"], json!([]));
        assert_eq!(capabilities["openid4vci"]["support"], "not_full_issuer");
        assert_eq!(capabilities["credential_profiles"][0]["id"], "profile-a");
        assert_eq!(
            capabilities["credential_profiles"][0]["format"],
            FORMAT_SD_JWT_VC
        );
        assert_eq!(
            document["credential_capabilities"]["unsupported_features"],
            json!([
                "application/vc+sd-jwt",
                "json_ld_vc_issuance",
                "data_integrity_proofs",
                "credential_status",
                "mso_mdoc",
                "openid4vci_full_issuer"
            ])
        );
    }

    #[test]
    fn service_document_preserves_output_when_self_attestation_disabled() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        assert_eq!(
            RegistryNotaryRuntime::service_document_with_self_attestation(
                &evidence,
                &SelfAttestationConfig::default(),
                false,
            ),
            RegistryNotaryRuntime::service_document(&evidence),
        );
    }

    #[test]
    fn claim_summary_exposes_claim_and_extract_field_semantics() {
        let mut claim = test_claim("date-of-birth", Vec::new(), true);
        claim.semantics = Some(registry_notary_core::ClaimSemanticConfig {
            concept: Some("https://publicschema.org/Person".to_string()),
            property: Some("https://publicschema.org/date_of_birth".to_string()),
            vocabulary: None,
            predicate: None,
            derived_from: Vec::new(),
            value_mapping: Some("publicschema".to_string()),
        });
        let summary = claim_summary(&claim);
        assert_eq!(
            summary["semantics"]["concept"],
            json!("https://publicschema.org/Person")
        );
        assert_eq!(
            summary["semantics"]["property"],
            json!("https://publicschema.org/date_of_birth")
        );
        assert_eq!(summary["semantics"]["value_mapping"], json!("publicschema"));

        let mut field_claim = test_claim("field-semantic", Vec::new(), true);
        field_claim
            .source_bindings
            .get_mut("src")
            .expect("source binding exists")
            .fields
            .get_mut("value")
            .expect("source field exists")
            .semantic_term = Some("https://publicschema.org/is_enrolled".to_string());
        let summary = claim_summary(&field_claim);
        assert_eq!(
            summary["semantics"]["property"],
            json!("https://publicschema.org/is_enrolled")
        );
    }

    #[test]
    fn service_document_redacts_self_attestation_details_when_not_authorized() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let self_attestation: SelfAttestationConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses");

        let document = RegistryNotaryRuntime::service_document_with_self_attestation(
            &evidence,
            &self_attestation,
            false,
        );

        assert_eq!(document["self_attestation"]["enabled"], json!(true));
        assert!(document["self_attestation"]["subject_id_type"].is_null());
        assert!(document["self_attestation"]["token_claim_name"].is_null());
        assert!(document["self_attestation"]["allowed_claim_ids"].is_null());
        assert!(document["self_attestation"]["credential_profile_ids"].is_null());
    }

    #[test]
    fn service_document_advertises_enabled_self_attestation_capabilities() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let self_attestation: SelfAttestationConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses");

        let document = RegistryNotaryRuntime::service_document_with_self_attestation(
            &evidence,
            &self_attestation,
            true,
        );

        assert_eq!(document["self_attestation"]["enabled"], json!(true));
        assert_eq!(
            document["self_attestation"]["allowed_operations"],
            json!({
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            })
        );
        assert_eq!(
            document["self_attestation"]["allowed_claim_ids"],
            json!(["person-is-alive"])
        );
        assert_eq!(
            document["self_attestation"]["allowed_formats"],
            json!([FORMAT_CLAIM_RESULT_JSON])
        );
        assert_eq!(
            document["self_attestation"]["allowed_disclosures"],
            json!(["predicate"])
        );
        assert_eq!(
            document["self_attestation"]["credential_profile_ids"],
            json!(["civil_status_sd_jwt"])
        );
        assert_eq!(
            document["self_attestation"]["subject_id_type"],
            json!("national_id")
        );
        assert_eq!(
            document["self_attestation"]["token_claim_name"],
            json!("https://id.example.gov/claims/national_id")
        );
        assert_eq!(
            document["self_attestation"]["required_scopes"],
            json!(["self_attestation"])
        );
        assert_eq!(
            document["self_attestation"]["scope_policy"],
            json!("required")
        );
        assert_eq!(
            document["self_attestation"]["max_evaluation_age_seconds"],
            json!(600)
        );
        assert_eq!(
            document["self_attestation"]["max_credential_validity_seconds"],
            json!(300)
        );
        assert_eq!(
            document["self_attestation"]["rate_limit_mode"],
            json!("in_process")
        );
        assert!(document["self_attestation"]["rate_limits"].is_null());
        assert!(document["self_attestation"]["allowed_wallet_origins"].is_null());
        assert!(document["self_attestation"]["citizen_clients"].is_null());
        assert!(document["self_attestation"]["token_policy"].is_null());
    }

    #[tokio::test]
    async fn evaluate_refuses_extract_result_that_violates_declared_value_type() {
        let source = Arc::new(WrongTypeSource);
        let mut evidence_config =
            (*test_evidence(vec![test_claim("selected", Vec::new(), true)])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err("extract result of the wrong JSON shape must be refused");

        assert!(matches!(err, EvidenceError::RuleEvaluationFailed));
    }

    #[tokio::test]
    async fn evaluate_refuses_exists_result_that_violates_declared_value_type() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.rule = RuleConfig::Exists {
            source: "src".to_string(),
        };
        claim.value.value_type = "string".to_string();
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err(
                "exists result of boolean shape must be refused against a declared string type",
            );

        assert!(matches!(err, EvidenceError::RuleEvaluationFailed));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evaluate_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config =
            (*test_evidence(vec![test_claim("selected", Vec::new(), true)])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.target = Some(registry_notary_core::EvidenceEntity::with_identifier(
            "Person",
            "national_id",
            "person-1",
        ));

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("evaluate succeeds");
        let target_ref =
            serde_json::to_value(&results[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn batch_item_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect("batch evaluate succeeds");
        let target_ref =
            serde_json::to_value(&response.items[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn bulk_prefetch_does_not_cache_rows_missing_required_fields() {
        let source = Arc::new(BulkInvalidThenDirectSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding")
            .connection = Some("bulk-source".to_string());
        claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding")
            .matching
            .allowed_purposes = vec!["test".to_string()];
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        evidence_config.source_connections =
            BTreeMap::from([("bulk-source".to_string(), bulk_source_connection())]);
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let memo = Arc::new(MemoState::new());
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions {
                    memo_observer: Some(&memo),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await
            .expect("batch evaluate succeeds after direct retry");

        assert_eq!(response.summary.succeeded, 1);
        assert_eq!(response.summary.failed, 0);
        assert!(matches!(
            response.items[0].status,
            BatchItemStatus::Succeeded
        ));
        assert_eq!(response.items[0].claim_results[0].value, Some(json!(true)));
        assert_eq!(source.bulk_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.direct_count.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 0);
        assert_eq!(memo.misses(), 1);
    }

    #[tokio::test]
    async fn bulk_prefetch_stale_row_is_not_disclosed() {
        let source = Arc::new(BulkStaleFreshnessSource::new());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        let binding = claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding");
        binding.connection = Some("bulk-source".to_string());
        binding.matching.allowed_purposes = vec!["test".to_string()];
        binding.matching.max_source_age_seconds = Some(60);
        binding.matching.source_observed_at_field = Some("observed_at".to_string());
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        evidence_config.source_connections =
            BTreeMap::from([("bulk-source".to_string(), bulk_source_connection())]);
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let memo = Arc::new(MemoState::new());
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions {
                    memo_observer: Some(&memo),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await
            .expect("batch evaluate reports per-item stale failure");

        assert_eq!(response.summary.succeeded, 0);
        assert_eq!(response.summary.failed, 1);
        assert!(matches!(response.items[0].status, BatchItemStatus::Failed));
        assert!(
            response.items[0].claim_results.is_empty(),
            "stale bulk values must not be disclosed"
        );
        assert!(
            response.items[0]
                .errors
                .iter()
                .any(|error| error.code == "pdp.evidence_stale"
                    && error.audit_code.as_deref() == Some("pdp.evidence_stale")),
            "expected stable stale freshness error, got {:?}",
            response.items[0].errors
        );
        assert_eq!(source.bulk_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            source.direct_count.load(Ordering::SeqCst),
            0,
            "stale preflight on cache miss must deny before direct protected row read"
        );
        assert_eq!(source.preflight_count.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 0);
    }

    #[tokio::test]
    async fn source_binding_lookup_can_use_prior_source_row_field() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let (sources, _, _, _) = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect("dependent source lookup succeeds");

        assert_eq!(sources["birth_event"]["id"], json!("birth-123"));
        let reads = source.reads.lock().expect("reads mutex is not poisoned");
        assert_eq!(
            reads.as_slice(),
            &[
                ("civil_status_record".to_string(), json!("person-1")),
                ("birth_event".to_string(), json!("birth-123")),
            ]
        );
    }

    #[tokio::test]
    async fn source_binding_lookup_missing_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row field fails");

        assert_collapsed_matching_error(error, "target.not_found");
    }

    #[tokio::test]
    async fn source_binding_lookup_missing_prior_field_preserves_error_when_collapse_disabled() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event =
            dependent_source_binding("birth_event", "sources.civil_status.birth_event_id", "id");
        birth_event.matching.collapse_matching_errors = false;
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row field fails");

        assert!(matches!(error, EvidenceError::SourceNotFound));
    }

    #[tokio::test]
    async fn source_binding_lookup_ambiguous_prior_rows_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!([
            {
                "person_id": "person-1",
                "birth_event_id": "birth-123"
            },
            {
                "person_id": "person-1",
                "birth_event_id": "birth-456"
            }
        ])));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("ambiguous source rows fail");

        assert_collapsed_matching_error(error, "target.match_ambiguous");
    }

    #[tokio::test]
    async fn source_binding_lookup_non_scalar_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": {
                "id": "birth-123"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row field fails");

        assert_collapsed_matching_error(error, "request.invalid");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_non_scalar_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": [
                "birth-123"
            ],
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row query field fails");

        assert_collapsed_matching_error(error, "request.invalid");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_missing_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row query field fails");

        assert_collapsed_matching_error(error, "target.not_found");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_ambiguous_prior_rows_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!([
            {
                "person_id": "person-1",
                "birth_event_id": "birth-123"
            },
            {
                "person_id": "person-1",
                "birth_event_id": "birth-456"
            }
        ])));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("ambiguous source rows query field fails");

        assert_collapsed_matching_error(error, "target.match_ambiguous");
    }

    #[tokio::test]
    async fn source_binding_lookup_non_scalar_prior_field_preserves_error_when_collapse_disabled() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": {
                "id": "birth-123"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event =
            dependent_source_binding("birth_event", "sources.civil_status.birth_event_id", "id");
        birth_event.matching.collapse_matching_errors = false;
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row field fails");

        assert!(matches!(error, EvidenceError::InvalidRequest));
    }

    #[tokio::test]
    async fn source_binding_ready_layer_materializes_before_spawning_reads() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
            "invalid_event_id": {
                "id": "birth-456"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "a_birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
            (
                "b_invalid_birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.invalid_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("invalid sibling materialization fails the ready layer");

        assert_collapsed_matching_error(error, "request.invalid");
        let reads = source.reads.lock().expect("reads mutex is not poisoned");
        assert_eq!(
            reads.as_slice(),
            &[("civil_status_record".to_string(), json!("person-1"))],
            "dependent sibling reads must not start until the whole ready layer materializes"
        );
    }

    #[tokio::test]
    async fn source_binding_lookup_unknown_dependency_is_invalid_request() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding("birth_event", "sources.missing.birth_event_id", "id"),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("unknown dependency source binding fails");

        assert!(matches!(error, EvidenceError::InvalidRequest));
        assert!(
            source
                .reads
                .lock()
                .expect("reads mutex is not poisoned")
                .is_empty(),
            "dependency discovery must fail before upstream reads"
        );
    }

    #[tokio::test]
    async fn source_binding_dependency_cycle_is_invalid_before_unrelated_reads() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "a_cycle".to_string(),
                dependent_source_binding("birth_event", "sources.b_cycle.birth_event_id", "id"),
            ),
            (
                "b_cycle".to_string(),
                dependent_source_binding("birth_event", "sources.a_cycle.birth_event_id", "id"),
            ),
            (
                "unrelated".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("source binding dependency cycle fails before source reads");

        assert!(matches!(error, EvidenceError::InvalidRequest));
        assert!(
            source
                .reads
                .lock()
                .expect("reads mutex is not poisoned")
                .is_empty(),
            "dependency graph validation must fail before unrelated ready reads"
        );
    }

    #[test]
    fn source_observed_at_from_row_trims_timestamp_before_parse() {
        let mut binding = test_source_binding();
        binding.matching.source_observed_at_field = Some("observed_at".to_string());

        let observed_at = source_observed_at_from_row(
            &binding,
            &json!({"observed_at": " 2026-05-24T12:00:00Z\n"}),
        )
        .expect("trimmed observed_at parses")
        .expect("observed_at is present");

        assert_eq!(
            observed_at
                .format(&Rfc3339)
                .expect("observed_at formats as RFC3339"),
            "2026-05-24T12:00:00Z"
        );
    }

    #[tokio::test]
    async fn evaluate_uses_requested_claim_version() {
        let source = Arc::new(CountingSource::default());
        let older_claim = test_claim("selected", Vec::new(), false);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let mut evidence_config = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("versioned evaluate succeeds");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(results[0].value, Some(json!(true)));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    /// REQ-SEC-G-005: the direct `evaluate` path must refuse a principal that
    /// lacks a claim's required scope, and must do so before any source read
    /// happens (`require_claim_access` runs ahead of `load_sources`). This
    /// mirrors the scope-denial coverage that already exists for federation
    /// and Relay call sites, using a counting fake source as the read probe.
    #[tokio::test]
    async fn evaluate_denies_missing_scope_before_reading_source() {
        let source = Arc::new(VersionScopedSource::default());
        let claim = test_claim("selected", Vec::new(), true);
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");
        let principal = EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect_err("principal without the claim's required scope must be denied");

        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "selected:1.0"
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn evaluate_authorizes_required_scope_from_requested_claim_version() {
        let source = Arc::new(VersionScopedSource::default());
        let older_claim = test_claim("selected", Vec::new(), true);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let mut evidence_config = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];
        let principal = EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: vec!["selected:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request.clone(),
                None,
            )
            .await
            .expect_err("version 1 scope must not authorize version 2");

        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "selected:2.0"
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);

        let principal = EvidencePrincipal {
            scopes: vec!["selected:2.0".to_string()],
            ..principal
        };
        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect("version 2 scope authorizes version 2");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn render_cccev_uses_result_claim_version_for_requirement() {
        let mut older_claim = test_claim("selected", Vec::new(), true);
        older_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v1".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v2".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let evidence = test_evidence(vec![older_claim, newer_claim]);
        let result = ClaimResultView {
            evaluation_id: "evaluation".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "2.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:target".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "value".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "runtime.test".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "2.0".to_string(),
                ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert_eq!(
            rendered["@graph"][0]["cccev:supportsRequirement"]["@id"],
            json!("https://requirements.example/v2")
        );
    }

    #[test]
    fn render_cccev_maps_provider_agent_from_generated_by_service_id() {
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let result = ClaimResultView {
            evaluation_id: "eval-test".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "1".to_string(),
            subject_type: "Person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:test".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "registry-notary".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "1".to_string(),
                ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert_eq!(
            rendered["@graph"][0]["cccev:isProvidedBy"]["dcterms:identifier"],
            json!("registry-notary"),
            "CCCEV provider agent must map from generated_by.service_id"
        );
    }

    #[test]
    fn render_cccev_omits_conformance_for_redacted_result() {
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let result = ClaimResultView {
            evaluation_id: "eval-test".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "1".to_string(),
            subject_type: "Person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:test".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: None,
            satisfied: None,
            disclosure: "redacted".to_string(),
            redacted_fields: vec!["selected".to_string()],
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "registry-notary".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "1".to_string(),
                ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert!(
            rendered["@graph"][0].get("cccev:isConformantTo").is_none(),
            "redacted CCCEV evidence must not reveal a false outcome"
        );
    }

    #[tokio::test]
    async fn evaluate_rejects_missing_claim_version() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err("unknown version is rejected");

        assert!(matches!(err, EvidenceError::ClaimVersionNotFound));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn requested_claim_versions_accepts_duplicate_same_version() {
        let versions = requested_claim_versions(&[
            ClaimRef::with_version("selected", "2.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect("duplicate matching version is accepted");

        assert_eq!(
            versions.get("selected").and_then(Option::as_deref),
            Some("2.0")
        );
    }

    #[test]
    fn requested_claim_versions_rejects_duplicate_conflicting_version() {
        let err = requested_claim_versions(&[
            ClaimRef::with_version("selected", "1.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect_err("conflicting versions are rejected");

        assert!(matches!(err, EvidenceError::InvalidRequest));
    }

    #[test]
    fn batch_input_validation_deduplicates_purposes() {
        let subjects = vec![
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-2".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-3".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
        ];
        let purposes = vec![
            "benefits".to_string(),
            "benefits".to_string(),
            "appeals".to_string(),
        ];

        let unique = validate_batch_inputs_and_collect_purposes(&subjects, &purposes)
            .expect("batch inputs are valid");

        assert_eq!(unique, BTreeSet::from(["appeals", "benefits"]));
    }

    #[test]
    fn value_disclosure_rejects_object_redaction_when_configured_field_is_absent() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "selected",
            json!({"name": "Ada"}),
            BTreeSet::from(["ssn".to_string()]),
        );

        let err = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("missing redaction field must fail value disclosure");

        assert!(matches!(err, EvidenceError::DisclosureNotAllowed));
    }

    #[test]
    fn value_disclosure_removes_every_configured_object_redaction_field() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "selected",
            json!({"name": "Ada", "ssn": "123", "case_id": "c-1"}),
            BTreeSet::from(["case_id".to_string(), "ssn".to_string()]),
        );

        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("configured fields are redacted");

        assert_eq!(view.value, Some(json!({"name": "Ada"})));
    }

    #[test]
    fn predicate_disclosure_rejects_redacted_claim_result() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.disclosure.allowed.push("predicate".to_string());
        let result = test_claim_result(
            "selected",
            json!(true),
            BTreeSet::from(["value".to_string()]),
        );

        let err = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Predicate,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("predicate disclosure must not bypass redaction");

        assert!(matches!(err, EvidenceError::DisclosureNotAllowed));
    }

    #[test]
    fn redacted_scalar_disclosure_reports_redacted_claim_id() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let claim = test_claim("opencrvs-age-band", Vec::new(), false);
        let result = test_claim_result("opencrvs-age-band", json!("child"), BTreeSet::new());

        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Redacted,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("scalar claim can be redacted");

        assert_eq!(view.value, None);
        assert_eq!(view.redacted_fields, vec!["opencrvs-age-band".to_string()]);
    }

    #[tokio::test]
    async fn issued_sd_jwt_disclosure_uses_view_claim_redacted_object_value() {
        const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("household-summary", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "household-summary",
            json!({
                "name": "Ada",
                "household_id": "hh-1",
                "ssn": "123-45-6789"
            }),
            BTreeSet::from(["ssn".to_string()]),
        );
        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("configured object field is redacted before issuance");
        assert_eq!(
            view.value,
            Some(json!({
                "name": "Ada",
                "household_id": "hh-1"
            }))
        );

        let issuer = registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
            RAW_JWK,
            "did:web:issuer.test#key-1".to_string(),
        )
        .expect("test issuer builds");
        let profile = CredentialProfileConfig {
            format: FORMAT_SD_JWT_VC.to_string(),
            issuer: "did:web:issuer.test".to_string(),
            signing_key: "issuer-key".to_string(),
            vct: "https://vct.example/test".to_string(),
            validity_seconds: 60,
            holder_binding: registry_notary_core::HolderBindingConfig {
                mode: "none".to_string(),
                proof_of_possession: None,
                allowed_did_methods: Vec::new(),
            },
            allowed_claims: Vec::new(),
            disclosure: Default::default(),
        };
        let signed = registry_notary_core::sd_jwt::issue(
            &profile,
            &issuer,
            &[view],
            "subject-ref",
            None,
            OffsetDateTime::UNIX_EPOCH,
            registry_notary_core::sd_jwt::IssueOptions::default(),
        )
        .await
        .expect("credential issues");
        let disclosures = signed
            .disclosures
            .iter()
            .map(|disclosure| {
                serde_json::from_slice::<Value>(
                    &URL_SAFE_NO_PAD
                        .decode(disclosure)
                        .expect("disclosure decodes as base64url"),
                )
                .expect("disclosure decodes as JSON")
            })
            .collect::<Vec<_>>();
        let disclosure = disclosures
            .iter()
            .find(|disclosure| disclosure.get(1) == Some(&json!("household-summary")))
            .expect("household-summary disclosure exists");
        let disclosure_json = serde_json::to_string(&disclosures).expect("disclosures serialize");

        assert_eq!(disclosure[2]["value"]["name"], json!("Ada"));
        assert_eq!(disclosure[2]["value"]["household_id"], json!("hh-1"));
        assert!(disclosure[2]["value"].get("ssn").is_none());
        assert!(!disclosure_json.contains("ssn"), "{disclosure_json}");
        assert!(
            !disclosure_json.contains("123-45-6789"),
            "{disclosure_json}"
        );
    }

    #[test]
    fn matching_pdp_decision_uses_shared_contract() {
        let mut binding = test_source_binding();
        binding.matching.allowed_purposes = vec!["benefits".to_string(), "appeals".to_string()];
        binding.matching.allowed_assurance = vec!["substantial".to_string()];
        let mut context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity {
                entity_type: "Person".to_string(),
                id: Some("person-1".to_string()),
                identifiers: Vec::new(),
                attributes: BTreeMap::new(),
                assurance: Some(registry_notary_core::EvidenceAssurance {
                    method: None,
                    level_scheme: None,
                    level: Some("substantial".to_string()),
                    verified_at: None,
                    issuer: None,
                    evidence: Vec::new(),
                }),
                profile: None,
            },
            relationship: None,
            on_behalf_of: None,
        };

        let default_trusted_policy = TrustedPolicyContext::default();
        let evidence = EvidenceConfig::default();
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::ASSURANCE_INSUFFICIENT,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "marketing",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::PURPOSE_NOT_PERMITTED,
        );
        context.target.assurance.as_mut().expect("assurance").level =
            Some("substantial".to_string());
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::ASSURANCE_INSUFFICIENT,
        );
        let trusted_policy = TrustedPolicyContext {
            assurance_level: Some("substantial".to_string()),
            ..TrustedPolicyContext::default()
        };
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(
                        &["pdp.purpose", "pdp.assurance_allowed_set"],
                        false,
                    ),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    trust_provenance: BTreeSet::from(["asserted_assurance".to_string()]),
                    ..PdpDecisionAudit::default()
                })
            }
        );

        binding.matching.permitted_jurisdictions = vec!["RW".to_string()];
        binding.matching.require_legal_basis = true;
        binding.matching.require_consent = true;
        binding.matching.redaction_fields = vec!["value".to_string()];
        let trusted_policy = TrustedPolicyContext {
            legal_basis_ref: Some("legal-basis:benefits".to_string()),
            consent_ref: Some("consent:person-1".to_string()),
            jurisdiction: Some("RW".to_string()),
            assurance_level: Some("substantial".to_string()),
            ..TrustedPolicyContext::default()
        };
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::from(["value".to_string()]),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(
                        &[
                            "pdp.purpose",
                            "pdp.jurisdiction",
                            "pdp.assurance_allowed_set",
                            "pdp.legal_basis_required",
                            "pdp.consent_required",
                        ],
                        true,
                    ),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    trust_provenance: BTreeSet::from([
                        "asserted_assurance".to_string(),
                        "consent_ref".to_string(),
                        "jurisdiction".to_string(),
                        "legal_basis_ref".to_string(),
                    ]),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        assert!(matching_purpose_policy_hash(&binding).starts_with("sha256:"));

        binding.matching.allowed_legal_basis_refs = vec!["legal-basis:other".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::LEGAL_BASIS_REQUIRED,
        );

        binding.matching.allowed_legal_basis_refs = vec!["legal-basis:benefits".to_string()];
        binding.matching.allowed_consent_refs = vec!["consent:other".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::CONSENT_REQUIRED,
        );

        binding.matching.allowed_consent_refs = vec!["consent:person-1".to_string()];
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect.audit.expect("permit audit").evaluated_rule_ids,
            matching_gate_rule_ids(
                &[
                    "pdp.purpose",
                    "pdp.jurisdiction",
                    "pdp.assurance_allowed_set",
                    "pdp.legal_basis_required",
                    "pdp.consent_required",
                    "pdp.legal_basis_allowed_set",
                    "pdp.consent_allowed_set",
                ],
                true,
            )
        );
    }

    #[test]
    fn default_matching_pdp_decision_records_permit_audit() {
        let binding = test_source_binding();
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        let effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
    }

    #[test]
    fn self_attestation_matching_pdp_uses_source_capability_instead_of_machine_scope() {
        let mut binding = test_source_binding();
        binding.required_scope = Some("people:evidence_verification".to_string());
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::CHECKED_SCOPE_REQUIRED,
        );

        let trusted_policy = TrustedPolicyContext {
            checked_scopes: BTreeSet::from(["people:evidence_verification".to_string()]),
            ..TrustedPolicyContext::default()
        };
        let machine_effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&["people:evidence_verification"]),
            &context,
            "benefits",
            &trusted_policy,
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert!(machine_effect
            .audit
            .expect("machine permit carries PDP audit")
            .evaluated_rule_ids
            .contains(&"source-binding-policy:person.checked_scope".to_string()));

        let self_attestation_effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &self_attestation_capability("person-is-alive"),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert!(!self_attestation_effect
            .audit
            .expect("self-attestation permit carries PDP audit")
            .evaluated_rule_ids
            .contains(&"source-binding-policy:person.checked_scope".to_string()));
    }

    #[test]
    fn matching_pdp_decision_enforces_requested_disclosure_and_format() {
        let binding = test_source_binding();
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Predicate,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::DISCLOSURE_NOT_PERMITTED,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_SD_JWT_VC,
                None,
                false,
            ),
            registry_platform_pdp::CREDENTIAL_FORMAT_NOT_PERMITTED,
        );
    }

    #[test]
    fn matching_pdp_decision_enforces_source_freshness_only_when_requested() {
        let mut binding = test_source_binding();
        binding.matching.max_source_age_seconds = Some(60);
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        let effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                true,
            ),
            registry_platform_pdp::EVIDENCE_STALE,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                Some(61),
                true,
            ),
            registry_platform_pdp::EVIDENCE_STALE,
        );
        let mut evidence = EvidenceConfig::default();
        evidence.ecosystem_bindings.insert(
            "oots-birth-evidence/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "lab.oots-birth-evidence.governed-evidence.v1".to_string(),
                policy_hash:
                    "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );
        binding.matching.ecosystem_binding =
            Some(registry_notary_core::EcosystemBindingSelectorConfig {
                id: Some("oots-birth-evidence/v1".to_string()),
                pack_id: Some("oots-birth-evidence/v1".to_string()),
                pack_version: Some("v1".to_string()),
                ..registry_notary_core::EcosystemBindingSelectorConfig::default()
            });
        let stale = matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            Some(61),
            true,
        )
        .expect_err("stale source denies with selected pack policy");
        let EvidenceError::PolicyDenied {
            code,
            policy_id: Some(policy_id),
            policy_hash: Some(policy_hash),
            ..
        } = stale
        else {
            panic!("expected pack-backed stale PolicyDenied");
        };
        assert_eq!(code, registry_platform_pdp::EVIDENCE_STALE);
        assert_eq!(policy_id, "lab.oots-birth-evidence.governed-evidence.v1");
        assert_eq!(
            policy_hash,
            "sha256:6666666666666666666666666666666666666666666666666666666666666666"
        );
        assert!(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            Some(60),
            true
        )
        .is_ok());
    }

    #[test]
    fn matching_policy_validation_preserves_stable_pdp_denials() {
        let mut binding = test_source_binding();
        binding.matching.allowed_purposes = vec!["benefits".to_string()];
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };
        let default_trusted_policy = TrustedPolicyContext::default();

        let error = validate_matching_policy(
            &EvidenceConfig::default(),
            &machine_capability(&[]),
            &[],
            &binding,
            &context,
            "marketing",
            &default_trusted_policy,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("wrong purpose must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::PURPOSE_NOT_PERMITTED,
                ..
            }
        ));

        binding.matching.allowed_assurance = vec!["substantial".to_string()];
        let error = validate_matching_policy(
            &EvidenceConfig::default(),
            &machine_capability(&[]),
            &[],
            &binding,
            &context,
            "benefits",
            &default_trusted_policy,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("insufficient assurance must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::ASSURANCE_INSUFFICIENT,
                ..
            }
        ));

        binding.matching.max_source_age_seconds = Some(60);
        let error = validate_matching_freshness_policy(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext {
                assurance_level: Some("substantial".to_string()),
                ..TrustedPolicyContext::default()
            },
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
        )
        .expect_err("missing source observation age must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::EVIDENCE_STALE,
                ..
            }
        ));

        binding.matching.collapse_matching_errors = true;
        assert!(matches!(
            collapse_matching_error(
                &binding,
                EvidenceError::PolicyDenied {
                    code: registry_platform_pdp::EVIDENCE_STALE,
                    policy_id: None,
                    policy_hash: None,
                    evaluated_rule_ids: Vec::new(),
                },
            ),
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::EVIDENCE_STALE,
                ..
            }
        ));
    }

    #[test]
    fn matching_pdp_decision_uses_selected_evidence_pack_identity() {
        let mut evidence = EvidenceConfig::default();
        evidence.ecosystem_bindings.insert(
            "civil-pack/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "evidence-pack-policy".to_string(),
                policy_hash:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );
        let mut binding = test_source_binding();
        binding.matching.ecosystem_binding =
            Some(registry_notary_core::EcosystemBindingSelectorConfig {
                id: Some("civil-pack/v1".to_string()),
                pack_id: Some("oots-birth-evidence/v1".to_string()),
                pack_version: Some("v1".to_string()),
                ..registry_notary_core::EcosystemBindingSelectorConfig::default()
            });
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };
        let purpose_constraints = test_purpose_constraints("benefits");

        let selected =
            selected_evidence_pack_policy(&evidence, &binding).expect("selected policy resolves");
        assert_eq!(selected.policy_id, "evidence-pack-policy");
        assert_eq!(selected.pack_id.as_deref(), Some("oots-birth-evidence/v1"));
        assert_eq!(selected.pack_version.as_deref(), Some("v1"));
        assert_eq!(
            selected.policy_hash,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: "evidence-pack-policy".to_string(),
                    policy_hash:
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_string(),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    ecosystem_binding_id: Some("civil-pack/v1".to_string()),
                    ecosystem_binding_version: Some("v1".to_string()),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        let identity = matching_policy_audit_identity(&evidence, &binding);
        assert_eq!(identity.pack_id.as_deref(), Some("oots-birth-evidence/v1"));
        assert_eq!(identity.pack_version.as_deref(), Some("v1"));

        evidence
            .ecosystem_bindings
            .get_mut("civil-pack/v1")
            .expect("binding exists")
            .unsupported_odrl_terms = vec!["odrl:targetPolicy".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::UNSUPPORTED_POLICY_TERM,
        );
    }

    #[tokio::test]
    async fn evaluate_claim_provenance_carries_selected_pack_identity() {
        let mut claim = test_claim("birth.certificate_summary", Vec::new(), true);
        claim.disclosure.default = "value".to_string();
        claim.disclosure.allowed = vec!["value".to_string(), "predicate".to_string()];
        let matching = &mut claim
            .source_bindings
            .get_mut("src")
            .expect("test source binding exists")
            .matching;
        matching.allowed_purposes = vec!["benefits".to_string()];
        matching.ecosystem_binding = Some(registry_notary_core::EcosystemBindingSelectorConfig {
            id: Some("oots-birth-evidence/v1".to_string()),
            pack_id: Some("oots-birth-evidence/v1".to_string()),
            pack_version: Some("v1".to_string()),
            ..registry_notary_core::EcosystemBindingSelectorConfig::default()
        });

        let mut evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };
        evidence.ecosystem_bindings.insert(
            "oots-birth-evidence/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "lab.oots-birth-evidence.governed-evidence.v1".to_string(),
                policy_hash:
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );

        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["birth.certificate_summary:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };
        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::new(evidence),
                Arc::new(VersionScopedSource::default()),
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![ClaimRef::from("birth.certificate_summary")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some("benefits".to_string()),
                },
                None,
            )
            .await
            .expect("claim evaluates");

        let generated_by = &results[0].provenance.generated_by;
        assert_eq!(
            generated_by.pack_id.as_deref(),
            Some("oots-birth-evidence/v1")
        );
        assert_eq!(generated_by.pack_version.as_deref(), Some("v1"));
        assert_eq!(results[0].disclosure, "value");
    }

    #[tokio::test]
    async fn batch_subject_purpose_conflict_rejects_batch_default() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 2;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 2;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-1".to_string(),
                        id_type: None,
                        purpose: Some("program-a".to_string()),
                    },
                ),
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-2".to_string(),
                        id_type: None,
                        purpose: None,
                    },
                ),
            ],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-b".to_string()),
        };

        let error = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("batch item purpose must not conflict with batch default");

        assert_eq!(error.code(), "request.invalid");
        assert!(source
            .purposes
            .lock()
            .expect("purposes mutex is not poisoned")
            .is_empty());
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_dependency_source_read_before_connector() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependency source read is not selected claim");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_rejects_context_hash_mismatch_before_source_read() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                delegated_attestation_capability(&keys, "NAT-123", "OTHER-CHILD"),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependent target hash must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_unproven_relationship_does_not_read_dependent_sources() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), false),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("false proof claim must deny delegated dependent evaluation");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedRelationshipUnproven
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_binds_target_id_type_not_just_value() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        // The capability pins the dependent target value CHILD-123 under the
        // national_id scheme, but the live request presents the same value under
        // civil_registration_id. Value-only hashing would have collided and let
        // the request through; binding the (id_type, id) pair fails closed before
        // any source read.
        let capability = delegated_attestation_capability_with_id_types(
            &keys,
            "national_id",
            "NAT-123",
            "national_id",
            "CHILD-123",
        );

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                capability,
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependent target id_type must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_binds_requester_id_type_not_just_value() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        // Mirror of the dependent-target test for the requester binding. The
        // capability pins the requester value NAT-123 under the civil_registration_id
        // scheme, but the live request presents the same value under national_id (and
        // the dependent target matches). Value-only hashing would have collided and
        // let the request through; binding the (id_type, id) pair fails closed before
        // any source read.
        let capability = delegated_attestation_capability_with_id_types(
            &keys,
            "civil_registration_id",
            "NAT-123",
            "civil_registration_id",
            "CHILD-123",
        );

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                capability,
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("requester id_type must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_arbitrary_requested_claim() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", Vec::new(), false),
            test_claim("other", Vec::new(), false),
        ]);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("other"),
                None,
                None,
                None,
            )
            .await
            .expect_err("self-attestation cannot switch claims after guard selection");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn machine_capability_preserves_dependency_source_read() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                SourceCapability::Machine {
                    scopes: BTreeSet::new(),
                },
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("machine source reads keep existing behavior");

        assert_eq!(results.len(), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn derived_claim_provenance_preserves_dependency_source_runtime() {
        let source = Arc::new(RuntimeSummarySource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                SourceCapability::Machine {
                    scopes: BTreeSet::new(),
                },
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("derived claim evaluates");

        assert_eq!(results.len(), 1);
        assert_eq!(source.inner.read_count.load(Ordering::SeqCst), 1);
        let runtimes = &results[0].provenance.used.source_runtimes;
        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].kind, SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR);
        assert_eq!(
            runtimes[0].config_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(runtimes[0].assurance.pinned);
        assert!(runtimes[0].assurance.runtime_verified);
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_root_bindings_redact_dependent_object_claim_values() {
        let mut dependency = test_claim("dependency", Vec::new(), false);
        dependency.value.value_type = "object".to_string();
        let selected = test_claim("selected", vec!["dependency"], false);
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![selected.clone(), dependency],
            ..EvidenceConfig::default()
        };
        let bindings = CelBindingsConfig {
            claims: BTreeMap::from([(
                "prior".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "dependency".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        };
        let claims = BTreeMap::from([(
            "dependency".to_string(),
            test_claim_result(
                "dependency",
                json!({
                    "name": "Ada",
                    "ssn": "123-45-6789"
                }),
                BTreeSet::from(["ssn".to_string()]),
            ),
        )]);
        let sources = BTreeMap::new();
        let target = EvidenceEntity::new("Person");
        let config = RegistryNotaryCelConfig::default();

        let root = cel_root_bindings(&CelEvaluationContext {
            evidence: &evidence,
            claim: &selected,
            expression: "claims.prior.value.ssn",
            bindings: &bindings,
            claims: &claims,
            sources: &sources,
            subject: None,
            target: &target,
            purpose: "benefits",
            today: "2026-06-18".to_string(),
            worker: None,
            config: &config,
        })
        .expect("CEL root bindings build");
        let prior = &root["claims"]["prior"];

        assert_eq!(prior["value"], json!({"name": "Ada"}));
        assert!(prior["value"].get("ssn").is_none());
        assert_eq!(prior["satisfied"], Value::Null);
    }

    #[tokio::test]
    async fn self_attestation_batch_is_denied_before_source_reads() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let err = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("self-attestation batch is not supported");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::BatchDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_binding_limits_reject_large_strings_and_lists() {
        let config = RegistryNotaryCelConfig {
            max_string_bytes: 4,
            max_list_items: 2,
            ..RegistryNotaryCelConfig::default()
        };

        assert!(validate_cel_binding_limits(&json!({ "value": "abcd" }), &config).is_ok());
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "value": "abcde" }), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "items": [1, 2, 3] }), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_policy_validation_rejects_invalid_alias_and_unlisted_dependency() {
        let claim = test_claim("cel-claim", vec!["dependency"], false);
        let invalid_alias = CelBindingsConfig {
            claims: BTreeMap::from([(
                "not-valid-alias".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "dependency".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        };
        assert!(matches!(
            validate_cel_policy(
                "true",
                &invalid_alias,
                &claim,
                &RegistryNotaryCelConfig::default()
            ),
            Err(EvidenceError::InvalidRequest)
        ));

        let unlisted_dependency = CelBindingsConfig {
            claims: BTreeMap::from([(
                "dep".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "other".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        };
        assert!(matches!(
            validate_cel_policy(
                "true",
                &unlisted_dependency,
                &claim,
                &RegistryNotaryCelConfig::default()
            ),
            Err(EvidenceError::InvalidRequest)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_accepts_date_source_field_dummy_values() {
        let mut source_binding = test_source_binding();
        source_binding.fields.insert(
            "birth_date".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "birth_date".to_string(),
                field_type: Some("date".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );

        let mut claim = test_claim("age-band", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([("civil".to_string(), source_binding)]);
        claim.rule = RuleConfig::Cel {
            expression: "date.age_on(source.civil.birth_date, ctx.today) >= 18".to_string(),
            bindings: CelBindingsConfig {
                claims: BTreeMap::new(),
                vars: BTreeMap::new(),
            },
        };
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };

        validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
            .expect("date-typed CEL bindings should preflight with valid dummy dates");
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_accepts_numeric_source_field_aliases() {
        let mut source_binding = test_source_binding();
        source_binding.fields.insert(
            "farm_area".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "farm_area".to_string(),
                field_type: Some("float".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        source_binding.fields.insert(
            "risk_score".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "risk_score".to_string(),
                field_type: Some("double".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );

        let mut claim = test_claim("small-farm-low-risk", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([("farm".to_string(), source_binding)]);
        claim.rule = RuleConfig::Cel {
            expression: "source.farm.farm_area < 4.0 && source.farm.risk_score <= 1.0".to_string(),
            bindings: CelBindingsConfig {
                claims: BTreeMap::new(),
                vars: BTreeMap::new(),
            },
        };
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };

        validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
            .expect("numeric CEL source field aliases should preflight as numbers");
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_rejects_unknown_roots_and_regex_usage() {
        assert!(validate_cel_expression_roots(
            "source.farmer.total_farmed_area < 4 && claims.prior.satisfied"
        )
        .is_ok());
        assert!(matches!(
            validate_cel_expression_roots("credential.level == 'gold'"),
            Err(EvidenceError::InvalidRequest)
        ));
        assert!(cel_expression_uses_regex(
            "source.person.name.matches('^A')"
        ));
        assert!(cel_expression_uses_regex(
            "text.regex_replace(source.person.name, '^A', 'B')"
        ));
        assert!(cel_expression_uses_regex(
            "text . regex_replace(source.person.name, '^A', 'B')"
        ));
        assert!(cel_expression_uses_regex(
            "text. regex_extract(source.person.name, '^(.+)$', 1)"
        ));
        assert!(cel_expression_uses_regex(
            "text_regex_extract(source.person.name, '^(.+)$', 1)"
        ));
        assert!(cel_expression_uses_regex(
            "validate.matches(source.person.name, '^A', 'bad')"
        ));
        assert!(!cel_expression_uses_regex(
            "'text.regex_replace(source.person.name, pattern)'"
        ));
    }

    #[test]
    fn claim_value_type_validation_matches_declared_json_shape() {
        assert!(validate_claim_value_type(&json!(true), "boolean").is_ok());
        assert!(validate_claim_value_type(&json!(1.5), "number").is_ok());
        assert!(validate_claim_value_type(&json!(1), "integer").is_ok());
        assert!(validate_claim_value_type(&json!("value"), "string").is_ok());
        assert!(validate_claim_value_type(&json!("2026-06-03"), "date").is_ok());
        assert!(validate_claim_value_type(&json!([1]), "array").is_ok());
        assert!(validate_claim_value_type(&json!({ "k": "v" }), "object").is_ok());
        assert!(validate_claim_value_type(&Value::Null, "null").is_ok());
        assert!(validate_claim_value_type(&json!("value"), "").is_ok());

        assert!(matches!(
            validate_claim_value_type(&json!("value"), "boolean"),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_claim_value_type(&json!(1.5), "integer"),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_claim_value_type(&json!(true), "unsupported"),
            Err(EvidenceError::InvalidRequest)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_binding_limits_reject_deep_json_without_recursive_walk() {
        let config = RegistryNotaryCelConfig::default();
        let mut value = json!(true);
        for _ in 0..=config.max_object_depth {
            value = json!({ "nested": value });
        }

        assert!(matches!(
            validate_cel_binding_limits(&value, &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_result_limits_reject_oversized_serialized_output() {
        let config = RegistryNotaryCelConfig {
            max_result_json_bytes: 4,
            ..RegistryNotaryCelConfig::default()
        };

        assert!(matches!(
            validate_cel_result_limits(&json!("12345"), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_result_limits_reject_deep_worker_output_without_recursive_walk() {
        let config = RegistryNotaryCelConfig::default();
        let mut value = json!(true);
        for _ in 0..=config.max_object_depth {
            value = json!({ "nested": value });
        }

        assert!(matches!(
            validate_cel_result_limits(&value, &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[test]
    fn credential_profile_for_rejects_profile_not_listed_in_claim() {
        // A caller-supplied credential_profile must be in the requested claim's
        // own credential_profiles allow-list. Otherwise a client could mint a
        // credential against a profile the claim never opted in to.
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
service_id: test.notary
claims:
  - id: claim-a
    title: A
    version: "1.0"
    subject_type: person
    rule:
      type: exists
      source: src
    credential_profiles:
      - profile_a
signing_keys:
  issuer-key:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY
    alg: EdDSA
    kid: did:web:issuer.example#key-1
    status: active
  issuer-key-b:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY_B
    alg: EdDSA
    kid: did:web:issuer.example#key-2
    status: active
credential_profiles:
  profile_a:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key
    vct: https://vct.example/a
    allowed_claims:
      - claim-a
  profile_b:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key-b
    vct: https://vct.example/b
    allowed_claims:
      - claim-a
"#,
        )
        .expect("evidence config is valid YAML");

        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: Vec::new(),
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect_err("profile_b is not listed on claim-a");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect("profile_a is listed on claim-a");
        assert_eq!(profile_id, "profile_a");
    }

    #[test]
    fn credential_profile_for_uses_stored_claim_version() {
        let mut older_claim = test_claim("claim-a", Vec::new(), true);
        older_claim.credential_profiles = vec!["profile_a".to_string()];
        let mut newer_claim = test_claim("claim-a", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.credential_profiles = vec!["profile_b".to_string()];
        let mut evidence = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence.credential_profiles = serde_norway::from_str(
            r#"
profile_a:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/a
  allowed_claims: [claim-a]
profile_b:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/b
  allowed_claims: [claim-a]
"#,
        )
        .expect("credential profiles parse");
        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: vec![ClaimRef::with_version("claim-a", "2.0")],
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect_err("profile_a is not listed on claim-a version 2.0");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect("profile_b is listed on claim-a version 2.0");
        assert_eq!(profile_id, "profile_b");
        let (profile_id, _) =
            credential_profile_for(&evidence, &evaluation, None).expect("default profile resolves");
        assert_eq!(profile_id, "profile_b");
    }
}
