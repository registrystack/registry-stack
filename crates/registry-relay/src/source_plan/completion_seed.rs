// SPDX-License-Identifier: Apache-2.0
//! Startup-only canonical completion-seed sizing.
//!
//! The compiler renders the complete state-plane seed shape from typed
//! artifacts, measures its largest request-dependent form, and retains only
//! the resulting byte count. Runtime code never reconstructs or reparses a
//! canonical artifact to establish this bound.

use registry_platform_audit::{
    DurableAuditOperationId, DurableAuditPhase, DurableAuditStreamKind, DurableAuditWrite,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Value};

use super::artifact::{
    IntegrationPackArtifact, PrivateBindingArtifact, PublicContractArtifact, SourcePlanKind,
    SourcePlanLimits,
};
use super::compiler::{RhaiWorkerLimits, SourcePlanCompileError};

pub(super) const MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1: usize = 768 * 1024;

pub(super) struct CompletionSeedSizing {
    pub(super) canonical_bytes_max: usize,
    pub(super) completion_audit_canonical_bytes_max: usize,
    #[cfg(test)]
    pub(super) canonical_value_max: Value,
}

pub(super) fn measure_completion_seed(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
    binding_hash: &str,
    effective_limits: SourcePlanLimits,
    effective_token_lifetime_ms: Option<u32>,
    rhai_limits: Option<RhaiWorkerLimits>,
) -> Result<CompletionSeedSizing, SourcePlanCompileError> {
    let operations = &pack.document.spec.plan.operations;
    let credential_operation = pack.document.spec.plan.credential_operation.as_ref();
    let mut authorized_operation_union = credential_operation
        .iter()
        .map(|operation| ("credential", operation.id.as_str()))
        .chain(
            operations
                .iter()
                .map(|operation| ("data", operation.id.as_str())),
        )
        .collect::<Vec<_>>();
    authorized_operation_union.sort_unstable();
    let authorized_operation_union = authorized_operation_union
        .into_iter()
        .map(|(kind, operation_id)| {
            json!({
                "kind": kind,
                "operation_id": operation_id,
            })
        })
        .collect::<Vec<_>>();
    let data_permit_operations = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => Vec::new(),
        SourcePlanKind::BoundedHttp => pack
            .document
            .spec
            .plan
            .steps
            .iter()
            .map(|operation| vec![operation.as_str()])
            .collect::<Vec<_>>(),
        SourcePlanKind::SandboxedRhai => {
            let limits = rhai_limits.ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let mut callable = operations
                .iter()
                .map(|operation| operation.id.as_str())
                .collect::<Vec<_>>();
            callable.sort_unstable();
            (0..limits.max_calls)
                .map(|_| callable.clone())
                .collect::<Vec<_>>()
        }
    };
    let mut permit_bindings = Vec::new();
    if let Some(operation) = credential_operation {
        permit_bindings.push(json!({
            "kind": "credential",
            "ordinal": 0,
            "allowed_operation_ids": [operation.id.as_str()],
        }));
    }
    permit_bindings.extend(
        data_permit_operations
            .iter()
            .enumerate()
            .map(|(ordinal, allowed)| {
                json!({
                    "kind": "data",
                    "ordinal": ordinal,
                    "allowed_operation_ids": allowed,
                })
            }),
    );
    let consent = &contract.document.spec.authorization.consent;
    let consent_verifier = consent.verifier.as_ref();
    let acquisition_fields = serde_json::to_value(&contract.document.spec.acquisition.fields)
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let disclosure_fields = contract
        .document
        .spec
        .output
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let public_outcomes = contract
        .document
        .spec
        .public_behavior
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            super::artifact::OutcomeDocument::Match => "match",
            super::artifact::OutcomeDocument::NoMatch => "no_match",
            super::artifact::OutcomeDocument::Ambiguous => "ambiguous",
        })
        .collect::<Vec<_>>();
    let data_destination_id = binding
        .data_destination_id
        .as_ref()
        .map(super::identifiers::SourceDestinationId::as_str);
    let credential_destination_id = binding
        .credential_destination_id
        .as_ref()
        .map(super::identifiers::SourceDestinationId::as_str);
    let credential_reference = binding
        .credential_reference
        .as_ref()
        .map(super::identifiers::CredentialReferenceId::as_str);
    let credential_generation = binding
        .document
        .credential
        .as_ref()
        .map(|credential| credential.generation);
    let operation_bounds = effective_limits.operation();
    let kind = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => "snapshot_exact",
        SourcePlanKind::BoundedHttp => "bounded_http",
        SourcePlanKind::SandboxedRhai => "sandboxed_rhai",
    };
    let acquisition_class = match contract.acquisition_class {
        crate::consultation::AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        crate::consultation::AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        crate::consultation::AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    };
    let credential_count = usize::from(credential_operation.is_some());
    if data_permit_operations.len() != usize::from(operation_bounds.max_data_exchanges) {
        return Err(SourcePlanCompileError::CompilerInvariant);
    }
    let mut seed = json!({
        "schema": "registry.relay.consultation-completion-seed/v1",
        "correlation": {"notary_evaluation_id": "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
        "profile": {
            "id": contract.identity().id().as_str(),
            "version": contract.identity().version().to_string(),
            "contract_hash": contract.identity().contract_hash().as_str(),
        },
        "integration_pack": {
            "id": pack.identity().id().as_str(),
            "version": pack.identity().version().to_string(),
            "hash": pack.identity().hash().as_str(),
        },
        "private_binding_hash": binding_hash,
        "workload": {
            "id": contract.workload_id.as_str(),
            "tenant_id": binding.tenant.as_str(),
            "registry_id": binding.registry_instance.as_str(),
        },
        "purpose": "",
        "policy": {
            "id": contract.policy_identity.id().as_str(),
            "hash": contract.policy_identity.hash().as_str(),
            "legal_basis_id": contract.legal_basis.as_str(),
            "consent": {
                "required": consent.required,
                "verifier_id": consent_verifier.map(|verifier| verifier.id.as_str()),
                "contract_hash": consent_verifier.map(|verifier| verifier.hash.as_str()),
                "decision": if consent.required { "verified" } else { "not_required" },
            },
            "obligations_digest": format!("sha256:{}", "f".repeat(64)),
        },
        "acquisition": {
            "class": acquisition_class,
            "schema": {
                "type": "acquisition_union",
                "fields": acquisition_fields,
            },
            "disclosure_fields": disclosure_fields,
            "public_outcomes": public_outcomes,
            "provenance_contract": {
                "source_observed_at": null,
                "source_revision": null,
                "snapshot_generation": if pack.document.spec.plan.kind == SourcePlanKind::SnapshotExact {
                    "required"
                } else {
                    "absent"
                },
                "snapshot_published_at": if pack.document.spec.plan.kind == SourcePlanKind::SnapshotExact {
                    "required"
                } else {
                    "absent"
                },
            },
        },
        "destinations": {
            "credential_destination_id": credential_destination_id,
            "data_destination_id": data_destination_id,
        },
        "credential": {
            "reference": credential_reference,
            "generation": credential_generation,
        },
        "authorized_operation_union": authorized_operation_union,
        "dispatch": {
            "plan_kind": kind,
            "permit_bindings": permit_bindings,
        },
        "bounds": {
            "source_matches": operation_bounds.max_source_matches,
            "disclosed_records": operation_bounds.max_disclosed_records,
            "data_exchanges": operation_bounds.max_data_exchanges,
            "credential_exchanges": credential_count,
            "data_destinations": operation_bounds.max_data_destinations,
            "source_bytes": operation_bounds.max_source_bytes,
            "timeout_ms": operation_bounds.timeout_ms,
            "max_in_flight": effective_limits.max_in_flight(),
            "quota_rate_per_minute": effective_limits.quota_per_minute(),
            "quota_burst": effective_limits.quota_burst(),
            "public_response_bytes": effective_limits.max_public_response_bytes(),
            "credential_token_lifetime_ms": effective_token_lifetime_ms,
        },
        "request_digest": format!("sha256:{}", "f".repeat(64)),
        "authorization_context_digest": format!("sha256:{}", "f".repeat(64)),
        "execution_plan_digest": format!("sha256:{}", "f".repeat(64)),
    });

    let mut maximum_seed = None::<(usize, Value)>;
    let mut completion_audit_canonical_bytes_max = 0;
    for purpose in &contract.purposes {
        seed["purpose"] = Value::String(purpose.as_str().to_owned());
        let canonical =
            canonicalize_json(&seed).map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
        if maximum_seed
            .as_ref()
            .is_none_or(|(size, _)| canonical.len() > *size)
        {
            maximum_seed = Some((canonical.len(), seed.clone()));
        }
        completion_audit_canonical_bytes_max =
            completion_audit_canonical_bytes_max.max(measure_completion_audit_payload(
                &seed,
                &data_permit_operations,
                credential_operation.map(|operation| operation.id.as_str()),
            )?);
    }
    let maximum_seed = maximum_seed.ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let canonical_bytes_max = maximum_seed.0;
    #[cfg(test)]
    let canonical_value_max = maximum_seed.1;
    Ok(CompletionSeedSizing {
        canonical_bytes_max,
        completion_audit_canonical_bytes_max,
        #[cfg(test)]
        canonical_value_max,
    })
}

fn measure_completion_audit_payload(
    seed: &Value,
    data_permit_operations: &[Vec<&str>],
    credential_operation: Option<&str>,
) -> Result<usize, SourcePlanCompileError> {
    let mut permit_evidence = Vec::new();
    let mut actual_path = Vec::new();
    if let Some(operation) = credential_operation {
        permit_evidence.push(json!({
            "kind": "credential",
            "ordinal": 0,
            "operation_id": operation,
            "dispatched_at_unix_us": 9_007_199_254_740_991_i64,
        }));
        actual_path.push(json!({
            "kind": "credential",
            "ordinal": 0,
            "operation_id": operation,
        }));
    }
    for (ordinal, allowed) in data_permit_operations.iter().enumerate() {
        let operation = allowed
            .iter()
            .max_by_key(|operation| operation.len())
            .copied()
            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
        permit_evidence.push(json!({
            "kind": "data",
            "ordinal": ordinal,
            "operation_id": operation,
            "dispatched_at_unix_us": 9_007_199_254_740_991_i64,
        }));
        actual_path.push(json!({
            "kind": "data",
            "ordinal": ordinal,
            "operation_id": operation,
        }));
    }
    let commitment = "x".repeat(1_024);
    let is_snapshot = seed["acquisition"]["class"] == "materialized_snapshot";
    let public_outcome = seed["acquisition"]["public_outcomes"]
        .as_array()
        .and_then(|outcomes| outcomes.last())
        .and_then(Value::as_str)
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let payload = json!({
        "attempt_event": {
            "envelope_id": "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "chain_hash": format!("registry-audit-chain-v1:{}", "f".repeat(64)),
        },
        "completion_seed": seed,
        "commitment_key_id": "k".repeat(96),
        "subject_handle": commitment,
        "input_commitment": "x".repeat(1_024),
        "predicate_commitment": "x".repeat(1_024),
        "consent_evidence_commitment": "x".repeat(1_024),
        "outcome": "known_complete",
        "permit_evidence": permit_evidence,
        "completion_facts": {
            "schema": "registry.relay.consultation-completion-facts/v1",
            "execution_result": {
                "class": "public_success",
                "outcome": public_outcome,
            },
            "provenance": {
                "relay_acquired_at_unix_ms": 9_007_199_254_740_991_i64,
                "source_observed_at_unix_ms": null,
                "source_revision": null,
                "snapshot_generation": is_snapshot.then_some("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"),
                "snapshot_published_at_unix_ms": is_snapshot
                    .then_some(9_007_199_254_740_991_i64),
            },
            "actual_credential_exchanges": usize::from(credential_operation.is_some()),
            "actual_data_exchanges": data_permit_operations.len(),
            "actual_path": actual_path,
        },
    });
    validate_completion_audit_payload(payload)
}

fn validate_completion_audit_payload(payload: Value) -> Result<usize, SourcePlanCompileError> {
    let canonical_bytes = canonicalize_json(&payload)
        .map(|canonical| canonical.len())
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let operation_id = DurableAuditOperationId::parse("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id,
        DurableAuditPhase::Completion,
        payload,
    )
    .map_err(|_| SourcePlanCompileError::CompletionAuditTooLarge)?;
    Ok(canonical_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_seed_and_audit_caps_leave_bounded_pseudonym_overhead() {
        const {
            assert!(
                super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1 + 8 * 1_024
                    < MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1
            );
        }
    }

    #[test]
    fn startup_audit_sizing_uses_the_authoritative_conservative_runtime_bound() {
        // `DurableAuditWrite` budgets every string for worst-case JSON escaping.
        // This payload is therefore near its authoritative bound even though
        // its all-ASCII canonical representation is much smaller.
        let maximum_ascii_bytes = (MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 - 38) / 6;
        let accepted = json!({"value": "x".repeat(maximum_ascii_bytes)});
        let canonical_bytes = validate_completion_audit_payload(accepted)
            .expect("exact conservative maximum is accepted at startup");
        assert!(canonical_bytes < MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1);

        let rejected = json!({"value": "x".repeat(maximum_ascii_bytes + 1)});
        assert_eq!(
            validate_completion_audit_payload(rejected),
            Err(SourcePlanCompileError::CompletionAuditTooLarge)
        );
    }

    #[test]
    fn exact_canonical_and_conservative_string_winners_can_differ() {
        let canonical_winner = "\"".repeat(200);
        let conservative_winner = "a".repeat(256);
        assert!(
            canonicalize_json(&json!({"purpose": canonical_winner}))
                .expect("canonical payload")
                .len()
                > canonicalize_json(&json!({"purpose": conservative_winner}))
                    .expect("canonical payload")
                    .len()
        );

        let accepts = |padding: usize, purpose: &str| {
            validate_completion_audit_payload(json!({
                "padding": "x".repeat(padding),
                "purpose": purpose,
            }))
            .is_ok()
        };
        let mut low = 0;
        let mut high = MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 / 6;
        while low < high {
            let midpoint = low + (high - low).div_ceil(2);
            if accepts(midpoint, &canonical_winner) {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        assert!(accepts(low, &canonical_winner));
        assert!(
            !accepts(low, &conservative_winner),
            "the longer raw purpose must win the authoritative conservative bound"
        );
    }
}
