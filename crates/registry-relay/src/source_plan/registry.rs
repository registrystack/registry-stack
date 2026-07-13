// SPDX-License-Identifier: Apache-2.0
//! Immutable, workload-visible consultation registry built at verified startup.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use thiserror::Error;

use crate::config::{VerifiedConsultationArtifactClosure, VerifiedEvidenceClass};
use crate::consultation::{
    AuthenticatedConsultationWorkload, ConsultationKey, IntegrationPackHash, OperationId,
    ProfileId, ProfileVersion, ResolvedConsultationProfile, WorkloadId,
};

use super::artifact::{
    parse_integration_pack, parse_private_binding, EvidenceClass, SourcePlanKind,
};
use super::compiler::{
    CompiledSourcePlan, CompiledSourcePlanRegistry, PinnedEvidenceArtifact,
    PinnedSourcePlanArtifact, RhaiWorkerCapability, SourcePlanArtifactBundle,
    SourcePlanCompileError,
};
use super::private_transport::PrivateTransportActivationError;
use super::runtime_profile::CompiledConsentProfile;

type ProfileKey = (ProfileId, ProfileVersion);
type ConsentVerifierKey = (OperationId, IntegrationPackHash);

/// Safe, value-free registry activation failure.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompiledConsultationRegistryError {
    #[error("consultation activation cannot compile an empty registry")]
    EmptyActivation,
    #[error("consultation source-plan compilation failed: {0}")]
    SourcePlan(#[from] SourcePlanCompileError),
    #[error("consultation Rhai script closure does not match reviewed packs")]
    RhaiArtifactClosureMismatch,
    #[error("consultation Rhai worker registry is not the exact initialized closure")]
    RhaiWorkerClosureMismatch,
    #[error("consultation consent verifier registry is not the exact initialized closure")]
    ConsentVerifierRegistryMismatch,
    #[error("consultation registry visibility index collided")]
    VisibilityCollision,
}

/// Opaque exact set of consent verifiers initialized before profile activation.
///
/// Configuration cannot construct this capability. The future consent runtime
/// mints it only after every verifier is initialized against its exact reviewed
/// contract hash. Extra initialized entries are rejected as unreferenced.
pub struct InitializedConsentVerifierRegistry {
    verifiers: BTreeSet<ConsentVerifierKey>,
}

impl fmt::Debug for InitializedConsentVerifierRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitializedConsentVerifierRegistry")
            .field("initialized_count", &self.verifiers.len())
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "minted by the future consent verifier startup integration"
)]
impl InitializedConsentVerifierRegistry {
    /// Close an initialized verifier set. This is intentionally crate-private:
    /// raw configuration references are not verifier capabilities.
    pub(crate) fn from_initialized(
        verifiers: impl IntoIterator<Item = ConsentVerifierKey>,
    ) -> Result<Self, CompiledConsultationRegistryError> {
        let mut closed = BTreeSet::new();
        for verifier in verifiers {
            if !closed.insert(verifier) {
                return Err(CompiledConsultationRegistryError::ConsentVerifierRegistryMismatch);
            }
        }
        Ok(Self { verifiers: closed })
    }

    pub(crate) const fn empty() -> Self {
        Self {
            verifiers: BTreeSet::new(),
        }
    }
}

/// Immutable registry compiled from one verified, closed startup bundle.
///
/// It retains compiled capabilities only. Raw artifact bytes, filesystem paths,
/// topology, and credential references are neither exposed nor included in its
/// redacted `Debug` output. There is no mutation or partial-apply API.
pub struct CompiledConsultationRegistry {
    source_plans: CompiledSourcePlanRegistry,
    visibility: BTreeMap<ProfileKey, WorkloadId>,
}

impl fmt::Debug for CompiledConsultationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledConsultationRegistry")
            .field("profile_count", &self.visibility.len())
            .finish()
    }
}

impl CompiledConsultationRegistry {
    #[cfg(test)]
    pub(crate) fn from_source_plans_for_test(source_plans: CompiledSourcePlanRegistry) -> Self {
        let visibility = source_plans
            .iter()
            .map(|plan| {
                (
                    (plan.profile().id().clone(), plan.profile().version()),
                    plan.runtime_profile().workload_id().clone(),
                )
            })
            .collect();
        Self {
            source_plans,
            visibility,
        }
    }

    /// Compile the complete verified startup closure atomically.
    ///
    /// Absence of artifacts is represented by absence of this registry, not an
    /// empty ready registry. Rhai workers and consent verifiers are non-config
    /// capabilities and must already be initialized exactly.
    #[allow(
        dead_code,
        reason = "called by the restart-only startup orchestration integration slice"
    )]
    pub(crate) fn compile(
        artifacts: VerifiedConsultationArtifactClosure,
        rhai_workers: &[RhaiWorkerCapability],
        consent_verifiers: &InitializedConsentVerifierRegistry,
    ) -> Result<Self, CompiledConsultationRegistryError> {
        if artifacts.public_contracts().is_empty() {
            return Err(CompiledConsultationRegistryError::EmptyActivation);
        }
        let required_rhai_workers = validate_rhai_artifact_closure(&artifacts)?;
        if rhai_workers.len() != required_rhai_workers {
            return Err(CompiledConsultationRegistryError::RhaiWorkerClosureMismatch);
        }

        let public_contracts = artifacts
            .public_contracts()
            .iter()
            .map(|artifact| {
                PinnedSourcePlanArtifact::new(artifact.bytes(), artifact.artifact_hash())
            })
            .collect::<Vec<_>>();
        let integration_packs = artifacts
            .integration_packs()
            .iter()
            .map(|artifact| {
                PinnedSourcePlanArtifact::new(artifact.bytes(), artifact.artifact_hash())
            })
            .collect::<Vec<_>>();
        let private_bindings = artifacts
            .private_bindings()
            .iter()
            .map(|artifact| artifact.bytes())
            .collect::<Vec<_>>();
        let evidence = artifacts
            .evidence()
            .iter()
            .map(|artifact| {
                PinnedEvidenceArtifact::new(
                    evidence_class(artifact.class()),
                    artifact.bytes(),
                    artifact.sha256(),
                )
            })
            .collect::<Vec<_>>();
        let bundle =
            SourcePlanArtifactBundle::new(&public_contracts, &integration_packs, &private_bindings)
                .with_evidence(&evidence)
                .with_rhai_workers(rhai_workers);
        let source_plans = CompiledSourcePlanRegistry::compile(&bundle)?;
        if source_plans.is_empty() {
            return Err(CompiledConsultationRegistryError::EmptyActivation);
        }

        let mut visibility = BTreeMap::new();
        let mut required_verifiers = BTreeSet::new();
        for plan in source_plans.iter() {
            let key = (plan.profile().id().clone(), plan.profile().version());
            if visibility
                .insert(key, plan.runtime_profile().workload_id().clone())
                .is_some()
            {
                return Err(CompiledConsultationRegistryError::VisibilityCollision);
            }
            if let CompiledConsentProfile::Required {
                verifier,
                contract_hash,
                ..
            } = plan.runtime_profile().authorization().consent()
            {
                required_verifiers.insert((verifier.clone(), contract_hash.clone()));
            }
        }
        if required_verifiers != consent_verifiers.verifiers {
            return Err(CompiledConsultationRegistryError::ConsentVerifierRegistryMismatch);
        }
        Ok(Self {
            source_plans,
            visibility,
        })
    }

    /// Number of enabled profile versions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.visibility.len()
    }

    /// A compiled activation registry is never constructible empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.visibility.is_empty()
    }

    /// Resolve only through the authenticated workload's exact visibility.
    #[must_use]
    #[allow(
        dead_code,
        reason = "consultation route activation is intentionally deferred beyond this startup slice"
    )]
    pub(crate) fn get_for_authenticated_workload(
        &self,
        key: &ConsultationKey,
        workload: &AuthenticatedConsultationWorkload,
    ) -> Option<&CompiledSourcePlan> {
        self.get_for_workload_id(key, workload.workload_id())
    }

    /// Resolve the plan and mint its workload-visible proof in one lookup so a
    /// caller cannot pair a proof with another profile version.
    #[allow(
        dead_code,
        reason = "consumed by the consultation service activation slice"
    )]
    pub(crate) fn resolve_for_authenticated_workload(
        &self,
        key: &ConsultationKey,
        workload: &AuthenticatedConsultationWorkload,
    ) -> Option<(ResolvedConsultationProfile, &CompiledSourcePlan)> {
        let plan = self.get_for_workload_id(key, workload.workload_id())?;
        Some((
            ResolvedConsultationProfile::from_authenticated_registry_plan(plan),
            plan,
        ))
    }

    /// Narrow source-plan access for restart-only source credential activation.
    /// This is visible only inside `source_plan`, never to request paths.
    pub(super) const fn source_plans_for_credentials(&self) -> &CompiledSourcePlanRegistry {
        &self.source_plans
    }

    /// Iterate the immutable plan closure for concrete Basic GET and exact
    /// OpenCRVS activation only. Request paths retain no registry-wide access.
    pub(crate) fn plans_for_concrete_activation(
        &self,
    ) -> impl ExactSizeIterator<Item = &CompiledSourcePlan> {
        self.source_plans.iter()
    }

    /// Load every hash-covered private CA and mTLS reference before this
    /// registry can be exposed to request handling.
    pub(crate) fn activate_private_transports(
        &mut self,
    ) -> Result<(), PrivateTransportActivationError> {
        self.source_plans.activate_private_transports()
    }

    fn get_for_workload_id(
        &self,
        key: &ConsultationKey,
        workload_id: &WorkloadId,
    ) -> Option<&CompiledSourcePlan> {
        let profile_key = (key.id().clone(), key.version());
        (self.visibility.get(&profile_key) == Some(workload_id))
            .then(|| self.source_plans.get(key.id(), key.version()))
            .flatten()
    }
}

/// Initialize the exact non-config Rhai worker capability closure from the
/// already verified artifact set. The reviewed script is compiled against the
/// production language surface before a capability can be minted; the normal
/// compiler pass then independently rechecks every callable and narrowed
/// limit against its private binding.
pub(crate) fn initialize_rhai_worker_capabilities(
    artifacts: &VerifiedConsultationArtifactClosure,
) -> Result<Vec<RhaiWorkerCapability>, CompiledConsultationRegistryError> {
    let required = validate_rhai_artifact_closure(artifacts)?;
    let bindings = artifacts
        .private_bindings()
        .iter()
        .map(|artifact| parse_private_binding(artifact.bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(SourcePlanCompileError::Artifact)?;
    let mut workers = Vec::with_capacity(required);
    for artifact in artifacts.integration_packs() {
        let pack = parse_integration_pack(artifact.bytes(), artifact.artifact_hash())
            .map_err(SourcePlanCompileError::Artifact)?;
        if pack.document.spec.plan.kind != SourcePlanKind::SandboxedRhai {
            continue;
        }
        let reviewed = pack
            .document
            .spec
            .plan
            .rhai
            .as_ref()
            .ok_or(CompiledConsultationRegistryError::RhaiArtifactClosureMismatch)?;
        let binding = bindings
            .iter()
            .find(|binding| binding.pack_identity == *pack.identity())
            .and_then(|binding| binding.document.capabilities.sandboxed_rhai.as_ref())
            .ok_or(CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?;
        let limits = super::compiler::RhaiWorkerLimits {
            max_calls: binding.max_calls,
            memory_bytes: binding.memory_bytes,
            cpu_ms: binding.cpu_ms,
            ipc_frame_bytes: binding.ipc_frame_bytes,
            instructions: binding.instructions,
            call_depth: binding.call_depth,
            string_bytes: binding.string_bytes,
            array_items: binding.array_items,
            map_entries: binding.map_entries,
            output_bytes: binding.output_bytes,
            concurrency: binding.concurrency,
        };
        let worker_limits = crate::rhai_worker::WorkerLimits {
            max_operations: limits.instructions,
            max_call_levels: usize::from(limits.call_depth),
            max_expr_depth: usize::from(limits.call_depth),
            max_string_bytes: usize::try_from(limits.string_bytes)
                .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?,
            max_array_items: usize::try_from(limits.array_items)
                .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?,
            max_map_entries: usize::try_from(limits.map_entries)
                .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?,
            max_output_bytes: usize::try_from(limits.output_bytes)
                .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?,
            max_ipc_frame_bytes: usize::try_from(limits.ipc_frame_bytes)
                .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?,
            max_memory_bytes: limits.memory_bytes,
            wall_time_ms: u64::from(limits.cpu_ms),
            max_source_calls: u32::from(limits.max_calls),
        };
        crate::rhai_worker::probe_script(&reviewed.script, &reviewed.entrypoint, worker_limits)
            .map_err(|_| CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)?;
        let callable = binding
            .callable_operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        workers.push(RhaiWorkerCapability::from_initialized_worker(
            pack.identity().hash().as_str(),
            &callable,
            limits,
        )?);
    }
    (workers.len() == required)
        .then_some(workers)
        .ok_or(CompiledConsultationRegistryError::RhaiWorkerClosureMismatch)
}

#[allow(
    dead_code,
    reason = "called by the restart-only startup orchestration integration slice"
)]
fn evidence_class(class: VerifiedEvidenceClass) -> EvidenceClass {
    match class {
        VerifiedEvidenceClass::Conformance => EvidenceClass::Conformance,
        VerifiedEvidenceClass::NegativeSecurity => EvidenceClass::NegativeSecurity,
        VerifiedEvidenceClass::Minimization => EvidenceClass::Minimization,
    }
}

#[allow(
    dead_code,
    reason = "called by the restart-only startup orchestration integration slice"
)]
fn validate_rhai_artifact_closure(
    artifacts: &VerifiedConsultationArtifactClosure,
) -> Result<usize, CompiledConsultationRegistryError> {
    let mut required_scripts = BTreeSet::new();
    let mut required_worker_count = 0_usize;
    for artifact in artifacts.integration_packs() {
        let pack = parse_integration_pack(artifact.bytes(), artifact.artifact_hash())
            .map_err(SourcePlanCompileError::Artifact)?;
        match (
            pack.document.spec.plan.kind,
            pack.document.spec.plan.rhai.as_ref(),
        ) {
            (SourcePlanKind::SandboxedRhai, Some(rhai)) => {
                required_worker_count += 1;
                required_scripts.insert(rhai.script_hash.clone());
            }
            (SourcePlanKind::SandboxedRhai, None) => {
                return Err(CompiledConsultationRegistryError::RhaiArtifactClosureMismatch)
            }
            (_, Some(_)) => {
                return Err(CompiledConsultationRegistryError::RhaiArtifactClosureMismatch)
            }
            (_, None) => {}
        }
    }
    let supplied = artifacts
        .rhai_scripts()
        .iter()
        .map(|artifact| artifact.sha256().to_owned())
        .collect::<BTreeSet<_>>();
    if required_scripts != supplied {
        return Err(CompiledConsultationRegistryError::RhaiArtifactClosureMismatch);
    }
    Ok(required_worker_count)
}

#[cfg(test)]
mod tests {
    use registry_platform_crypto::{canonicalize_json, parse_json_strict};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::source_plan::compiler::RhaiWorkerLimits;

    const PACK_DOMAIN: &[u8] = b"registry.relay.integration-pack.v1\0";
    const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
    const POLICY_DOMAIN: &[u8] = b"registry.relay.consultation-policy.v1\0";
    const CONTRACT: &[u8] =
        include_bytes!("../../tests/fixtures/source-plan-v1/public-contract.json");
    const PACK: &[u8] = include_bytes!("../../tests/fixtures/source-plan-v1/integration-pack.json");
    const BINDING: &[u8] =
        include_bytes!("../../tests/fixtures/source-plan-v1/private-binding.json");
    const CONFORMANCE: &[u8] = b"synthetic registry conformance evidence v1\n";
    const NEGATIVE_SECURITY: &[u8] = b"synthetic registry negative security evidence v1\n";
    const MINIMIZATION: &[u8] = b"synthetic registry minimization proof v1\n";
    const RHAI_SCRIPT: &str = "fn consult(ctx) { result.no_match() }";

    fn raw_hash(bytes: &[u8]) -> String {
        let mut encoded = String::from("sha256:");
        for byte in Sha256::digest(bytes) {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    fn typed_hash(domain: &[u8], bytes: &[u8]) -> String {
        let value = parse_json_strict(bytes).unwrap();
        let canonical = canonicalize_json(&value).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(canonical);
        let mut encoded = String::from("sha256:");
        for byte in hasher.finalize() {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    fn policy_preimage(contract: &Value) -> Value {
        let authorization = &contract["spec"]["authorization"];
        let policy = &authorization["policy"];
        json!({
            "schema": "registry.relay.consultation-policy.v1",
            "enforcement_profile": "registry.relay.consultation-pdp/v1",
            "rule_set": "registry.relay.consultation-policy-rules.v1",
            "id": policy["id"].clone(),
            "action": "consultation_execute",
            "target": {
                "profile": {"id": contract["id"].clone(), "version": contract["version"].clone()},
                "integration_pack": contract["spec"]["integration_pack"].clone()
            },
            "authorization": {
                "workload": authorization["workload"].clone(),
                "required_scope": authorization["required_scope"].clone(),
                "purposes": authorization["purposes"].clone(),
                "legal_basis": authorization["legal_basis"].clone(),
                "consent": authorization["consent"].clone(),
                "mandatory_obligations": authorization["mandatory_obligations"].clone()
            },
            "decision": {
                "permit": "unqualified",
                "decision_cache": policy["decision_cache"].clone(),
                "max_decision_age_ms": policy["max_decision_age_ms"].clone(),
                "unavailable": policy["unavailable"].clone()
            }
        })
    }

    fn closure(contract: Vec<u8>, contract_hash: String) -> VerifiedConsultationArtifactClosure {
        VerifiedConsultationArtifactClosure::from_parts_for_test(
            vec![(contract, contract_hash)],
            vec![(PACK.to_vec(), typed_hash(PACK_DOMAIN, PACK))],
            vec![BINDING.to_vec()],
            fixture_evidence(),
            Vec::new(),
        )
    }

    fn fixture_evidence() -> Vec<(VerifiedEvidenceClass, Vec<u8>, String)> {
        vec![
            (
                VerifiedEvidenceClass::Conformance,
                CONFORMANCE.to_vec(),
                raw_hash(CONFORMANCE),
            ),
            (
                VerifiedEvidenceClass::NegativeSecurity,
                NEGATIVE_SECURITY.to_vec(),
                raw_hash(NEGATIVE_SECURITY),
            ),
            (
                VerifiedEvidenceClass::Minimization,
                MINIMIZATION.to_vec(),
                raw_hash(MINIMIZATION),
            ),
        ]
    }

    fn closure_with_evidence(
        public_contracts: Vec<(Vec<u8>, String)>,
        evidence: Vec<(VerifiedEvidenceClass, Vec<u8>, String)>,
    ) -> VerifiedConsultationArtifactClosure {
        VerifiedConsultationArtifactClosure::from_parts_for_test(
            public_contracts,
            vec![(PACK.to_vec(), typed_hash(PACK_DOMAIN, PACK))],
            vec![BINDING.to_vec()],
            evidence,
            Vec::new(),
        )
    }

    fn rhai_pack(id: &str) -> (Vec<u8>, String) {
        let mut pack = parse_json_strict(PACK).unwrap();
        pack["id"] = json!(id);
        pack["spec"]["bounds"]["max_source_matches"] = json!(1);
        pack["spec"]["acquisition"]["class"] = json!("bounded_full_record");
        pack["spec"]["reviewed_acquisition"]["class"] = json!("bounded_full_record");
        pack["spec"]["reviewed_acquisition"]["selector"] = Value::Null;
        pack["spec"]["reviewed_acquisition"]["cardinality"] = json!("source_enforced_singleton");
        pack["spec"]["plan"]["kind"] = json!("sandboxed_rhai");
        pack["spec"]["plan"]["steps"] = json!([]);
        pack["spec"]["plan"]
            .as_object_mut()
            .expect("Rhai plan")
            .remove("step_conditions");
        let operation = &mut pack["spec"]["plan"]["operations"][0];
        operation["query"] = json!({});
        operation["headers"] = json!({});
        let operation_object = operation.as_object_mut().expect("Rhai operation");
        operation_object.remove("path_parameters");
        operation_object.remove("relation_selector");
        operation_object.remove("input_selector");
        operation["acquisition_fields"] = json!([]);
        operation["control_fields"] = json!([]);
        operation["projection"] = json!({"mechanism": "bounded_full_record"});
        operation["response"] = json!({
            "max_bytes": 65536,
            "max_records": 1,
            "normalization": "script_body",
            "cardinality": {"mechanism": "script_managed"},
            "schema": {"type": "script_body"},
            "output_mapping": {}
        });
        pack["spec"]["plan"]["rhai"] = json!({
            "script": RHAI_SCRIPT,
            "script_hash": raw_hash(RHAI_SCRIPT.as_bytes()),
            "entrypoint": "consult",
            "memory_bytes": 67108864,
            "cpu_ms": 500,
            "ipc_frame_bytes": 131072,
            "instructions": 50000,
            "call_depth": 8,
            "string_bytes": 32768,
            "array_items": 256,
            "map_entries": 256,
            "output_bytes": 32768,
            "concurrency": 1
        });
        let bytes = serde_json::to_vec(&pack).unwrap();
        let hash = typed_hash(PACK_DOMAIN, &bytes);
        (bytes, hash)
    }

    fn rhai_closure() -> (VerifiedConsultationArtifactClosure, String) {
        let (pack, pack_hash) = rhai_pack("synthetic.person-status");
        let mut contract = parse_json_strict(CONTRACT).unwrap();
        contract["spec"]["integration_pack"]["hash"] = json!(pack_hash);
        contract["spec"]["runtime"] = json!({
            "platform_profile": "registry-stack.consultation.v1",
            "source_capability": "script",
            "script_abi": crate::rhai_worker::xw::XW_ABI_VERSION
        });
        contract["spec"]["bounds"]["max_source_matches"] = json!(1);
        contract["spec"]["acquisition"]["class"] = json!("bounded_full_record");
        contract["spec"]["public_behavior"]["outcomes"] = json!(["match", "no_match"]);
        let policy_bytes = serde_json::to_vec(&policy_preimage(&contract)).unwrap();
        contract["spec"]["authorization"]["policy"]["hash"] =
            json!(typed_hash(POLICY_DOMAIN, &policy_bytes));
        let contract = serde_json::to_vec(&contract).unwrap();
        let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);

        let mut binding = parse_json_strict(BINDING).unwrap();
        binding["integration_pack"]["hash"] = json!(pack_hash);
        binding["capabilities"]["allow_sandboxed_rhai"] = json!(true);
        binding["capabilities"]["sandboxed_rhai"] = json!({
            "callable_operations": ["lookup-status"],
            "max_calls": 1,
            "memory_bytes": 67108864,
            "cpu_ms": 500,
            "ipc_frame_bytes": 131072,
            "instructions": 50000,
            "call_depth": 8,
            "string_bytes": 32768,
            "array_items": 256,
            "map_entries": 256,
            "output_bytes": 32768,
            "concurrency": 1,
            "isolation": "one_shot_worker_v1"
        });
        let binding = serde_json::to_vec(&binding).unwrap();

        (
            VerifiedConsultationArtifactClosure::from_parts_for_test(
                vec![(contract, contract_hash)],
                vec![(pack, pack_hash.clone())],
                vec![binding],
                fixture_evidence(),
                vec![(
                    RHAI_SCRIPT.as_bytes().to_vec(),
                    raw_hash(RHAI_SCRIPT.as_bytes()),
                )],
            ),
            pack_hash,
        )
    }

    fn rhai_worker(pack_hash: &str) -> RhaiWorkerCapability {
        RhaiWorkerCapability::from_initialized_worker(
            pack_hash,
            &["lookup-status"],
            RhaiWorkerLimits {
                max_calls: 1,
                memory_bytes: 67_108_864,
                cpu_ms: 500,
                ipc_frame_bytes: 131_072,
                instructions: 50_000,
                call_depth: 8,
                string_bytes: 32_768,
                array_items: 256,
                map_entries: 256,
                output_bytes: 32_768,
                concurrency: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn lookup_is_exactly_profile_version_and_workload_visible() {
        let artifacts = closure(CONTRACT.to_vec(), typed_hash(CONTRACT_DOMAIN, CONTRACT));
        let registry = CompiledConsultationRegistry::compile(
            artifacts,
            &[],
            &InitializedConsentVerifierRegistry::empty(),
        )
        .expect("fixture compiles");
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert_eq!(
            format!("{registry:?}"),
            "CompiledConsultationRegistry { profile_count: 1 }"
        );
        let key = ConsultationKey::try_parse("synthetic.person-status.exact", "1").unwrap();
        let visible = WorkloadId::try_from("registry-notary").unwrap();
        let hidden = WorkloadId::try_from("another-workload").unwrap();
        assert!(registry.get_for_workload_id(&key, &visible).is_some());
        let workload = AuthenticatedConsultationWorkload::for_runtime_vector_test(i64::MAX / 2);
        let (resolved, plan) = registry
            .resolve_for_authenticated_workload(&key, &workload)
            .expect("authenticated workload receives plan and proof together");
        assert_eq!(resolved.key(), &key);
        let core = crate::consultation::PreAuthorizationConsultationCore::from_resolved_plan(
            resolved,
            plan,
            crate::consultation::ParsedPurpose::try_parse("benefit-verification").unwrap(),
            crate::consultation::ParsedConsultationInputs::try_parse("subject_id", "12345")
                .unwrap(),
        )
        .expect("resolved proof binds the exact plan");
        assert_eq!(core.profile(), plan.profile());
        crate::source_plan::CompiledBasicSourceCredentialProvider::compile_for_consultations(
            &crate::config::ConsultationSourceCredentialCatalogConfig::default(),
            &registry,
        )
        .expect("OAuth-only consultation activation has an empty Basic credential closure");
        assert!(registry.get_for_workload_id(&key, &hidden).is_none());
        assert!(registry
            .get_for_workload_id(
                &ConsultationKey::try_parse("synthetic.person-status.exact", "2").unwrap(),
                &visible,
            )
            .is_none());
    }

    #[test]
    fn consent_activation_requires_the_exact_initialized_registry() {
        let mut contract = parse_json_strict(CONTRACT).unwrap();
        contract["spec"]["authorization"]["consent"] = json!({
            "required": true,
            "verifier": {
                "id": "registry.consent.v1",
                "hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            },
            "max_age_ms": 60000,
            "revocation": "online_required",
            "unavailable": "deny"
        });
        let policy_bytes = serde_json::to_vec(&policy_preimage(&contract)).unwrap();
        contract["spec"]["authorization"]["policy"]["hash"] =
            Value::String(typed_hash(POLICY_DOMAIN, &policy_bytes));
        let contract = serde_json::to_vec(&contract).unwrap();
        let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);

        assert_eq!(
            CompiledConsultationRegistry::compile(
                closure(contract.clone(), contract_hash.clone()),
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::ConsentVerifierRegistryMismatch
        );

        let verifier = (
            OperationId::try_from("registry.consent.v1").unwrap(),
            IntegrationPackHash::try_from(
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .unwrap(),
        );
        let initialized = InitializedConsentVerifierRegistry::from_initialized([verifier]).unwrap();
        assert!(CompiledConsultationRegistry::compile(
            closure(contract.clone(), contract_hash.clone()),
            &[],
            &initialized,
        )
        .is_ok());

        let initialized_with_extra = InitializedConsentVerifierRegistry::from_initialized([
            (
                OperationId::try_from("registry.consent.v1").unwrap(),
                IntegrationPackHash::try_from(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )
                .unwrap(),
            ),
            (
                OperationId::try_from("registry.consent.unreferenced").unwrap(),
                IntegrationPackHash::try_from(
                    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                )
                .unwrap(),
            ),
        ])
        .unwrap();
        assert_eq!(
            CompiledConsultationRegistry::compile(
                closure(contract, contract_hash),
                &[],
                &initialized_with_extra,
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::ConsentVerifierRegistryMismatch
        );
    }

    #[test]
    fn activation_rejects_empty_or_colliding_profiles() {
        let empty = VerifiedConsultationArtifactClosure::from_parts_for_test(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            CompiledConsultationRegistry::compile(
                empty,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::EmptyActivation
        );

        let contract_hash = typed_hash(CONTRACT_DOMAIN, CONTRACT);
        let duplicate = closure_with_evidence(
            vec![
                (CONTRACT.to_vec(), contract_hash.clone()),
                (CONTRACT.to_vec(), contract_hash),
            ],
            fixture_evidence(),
        );
        assert_eq!(
            CompiledConsultationRegistry::compile(
                duplicate,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::SourcePlan(SourcePlanCompileError::DuplicateProfile,)
        );
    }

    #[test]
    fn evidence_closure_rejects_missing_extra_and_wrong_class() {
        let contracts = vec![(CONTRACT.to_vec(), typed_hash(CONTRACT_DOMAIN, CONTRACT))];
        let mut missing_evidence = fixture_evidence();
        missing_evidence.remove(0);
        let missing = closure_with_evidence(contracts.clone(), missing_evidence);
        assert_eq!(
            CompiledConsultationRegistry::compile(
                missing,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::SourcePlan(SourcePlanCompileError::MissingEvidence,)
        );

        let mut extra_evidence = fixture_evidence();
        let extra_bytes = b"unreferenced evidence";
        extra_evidence.push((
            VerifiedEvidenceClass::Conformance,
            extra_bytes.to_vec(),
            raw_hash(extra_bytes),
        ));
        let extra = closure_with_evidence(contracts.clone(), extra_evidence);
        assert_eq!(
            CompiledConsultationRegistry::compile(
                extra,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::SourcePlan(SourcePlanCompileError::ExtraEvidence,)
        );

        let mut wrong_class_evidence = fixture_evidence();
        wrong_class_evidence[0].0 = VerifiedEvidenceClass::Minimization;
        let wrong_class = closure_with_evidence(contracts, wrong_class_evidence);
        assert_eq!(
            CompiledConsultationRegistry::compile(
                wrong_class,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::SourcePlan(
                SourcePlanCompileError::MisclassifiedEvidence,
            )
        );
    }

    #[test]
    fn missing_or_unreferenced_rhai_script_fails_closed() {
        let artifacts = closure(CONTRACT.to_vec(), typed_hash(CONTRACT_DOMAIN, CONTRACT));
        let extra_script = VerifiedConsultationArtifactClosure::from_parts_for_test(
            artifacts
                .public_contracts()
                .iter()
                .map(|artifact| {
                    (
                        artifact.bytes().to_vec(),
                        artifact.artifact_hash().to_owned(),
                    )
                })
                .collect(),
            artifacts
                .integration_packs()
                .iter()
                .map(|artifact| {
                    (
                        artifact.bytes().to_vec(),
                        artifact.artifact_hash().to_owned(),
                    )
                })
                .collect(),
            artifacts
                .private_bindings()
                .iter()
                .map(|artifact| artifact.bytes().to_vec())
                .collect(),
            artifacts
                .evidence()
                .iter()
                .map(|artifact| {
                    (
                        artifact.class(),
                        artifact.bytes().to_vec(),
                        artifact.sha256().to_owned(),
                    )
                })
                .collect(),
            vec![(
                b"unreferenced script".to_vec(),
                raw_hash(b"unreferenced script"),
            )],
        );
        assert_eq!(
            CompiledConsultationRegistry::compile(
                extra_script,
                &[],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::RhaiArtifactClosureMismatch
        );
    }

    #[test]
    fn rhai_worker_registry_rejects_unreferenced_capabilities() {
        let no_rhai = closure(CONTRACT.to_vec(), typed_hash(CONTRACT_DOMAIN, CONTRACT));
        let extra_worker =
            rhai_worker("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        assert_eq!(
            CompiledConsultationRegistry::compile(
                no_rhai,
                &[extra_worker],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::RhaiWorkerClosureMismatch
        );

        let (rhai, pack_hash) = rhai_closure();
        let required_worker = rhai_worker(&pack_hash);
        let extra_worker =
            rhai_worker("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        assert_eq!(
            CompiledConsultationRegistry::compile(
                rhai,
                &[required_worker, extra_worker],
                &InitializedConsentVerifierRegistry::empty(),
            )
            .unwrap_err(),
            CompiledConsultationRegistryError::RhaiWorkerClosureMismatch
        );

        let (rhai, pack_hash) = rhai_closure();
        CompiledConsultationRegistry::compile(
            rhai,
            &[rhai_worker(&pack_hash)],
            &InitializedConsentVerifierRegistry::empty(),
        )
        .expect("exact reviewed Rhai worker closes activation");
    }

    #[test]
    fn verified_rhai_closure_initializes_the_exact_worker_capability() {
        let (artifacts, _) = rhai_closure();
        let workers = initialize_rhai_worker_capabilities(&artifacts)
            .expect("reviewed script probes under the production worker surface");
        assert_eq!(workers.len(), 1);
        CompiledConsultationRegistry::compile(
            artifacts,
            &workers,
            &InitializedConsentVerifierRegistry::empty(),
        )
        .expect("initialized exact Rhai closure activates");
    }

    #[test]
    fn distinct_rhai_packs_may_share_one_closed_script_artifact() {
        let (first_pack, first_hash) = rhai_pack("synthetic.person-status");
        let (second_pack, second_hash) = rhai_pack("synthetic.person-status-secondary");
        let artifacts = VerifiedConsultationArtifactClosure::from_parts_for_test(
            Vec::new(),
            vec![(first_pack, first_hash), (second_pack, second_hash)],
            Vec::new(),
            Vec::new(),
            vec![(
                RHAI_SCRIPT.as_bytes().to_vec(),
                raw_hash(RHAI_SCRIPT.as_bytes()),
            )],
        );

        assert_eq!(validate_rhai_artifact_closure(&artifacts), Ok(2));
    }
}
