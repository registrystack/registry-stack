// SPDX-License-Identifier: Apache-2.0
//! Native Proposal observers share the ordinary governed delivery mechanism.

use crate::compiler::{
    HOOK_ATTEMPT_TIMEOUT_MS, HOOK_BACKOFF_MULTIPLIER, HOOK_INITIAL_BACKOFF_MS,
    HOOK_MAXIMUM_ATTEMPTS, HOOK_MAXIMUM_BACKOFF_MS,
};
use crate::contract::{
    ActionExecutionSource, Classification, HookAuthenticationProfile, HookDeadLetterMode,
    HookHandlerSource, ModuleAssetSource, ProposalEventTransition,
};
use crate::diagnostics::Diagnostic;
use crate::immediate_actions::CollectedActionSource;
use crate::model::*;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_hooks::HOOK_HANDLER_ABI_V1;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PROPOSAL_EVENT_SCHEMA: &str =
    "https://id.registrystack.org/contracts/breg/proposal-event/v1";
pub const PROPOSAL_EVENT_SCHEMA_PATH: &str =
    "generated/event-schemas/proposal-lifecycle.schema.json";
/// Fixed metadata only. This bound applies to the complete canonical envelope.
pub const MAX_PROPOSAL_EVENT_PAYLOAD_BYTES: u32 = 8192;

pub fn proposal_event_schema() -> Value {
    let digest = json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    let nullable_digest = json!({"anyOf":[digest.clone(),{"type":"null"}]});
    let states =
        json!({"type":"string","enum":["draft","submitted","applied","cancelled","rejected"]});
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":PROPOSAL_EVENT_SCHEMA,
        "type":"object","additionalProperties":false,
        "required":["actionId","actionRevision","proposalId","submissionVersion","revision","fromState","state","transition","effectDigest","authorityKind","systemApplyGrantRevision","turn"],
        "properties":{
            "actionId":{"type":"string","minLength":1,"maxLength":64},
            "actionRevision":digest,"proposalId":{"type":"string","format":"uuid"},
            "submissionVersion":{"type":"integer","minimum":1,"maximum":4294967295u64},
            "revision":{"type":"integer","minimum":1,"maximum":9007199254740991u64},
            "fromState":{"anyOf":[states.clone(),{"const":"none"}]},"state":states,
            "transition":{"type":"string","enum":["started","edited","submitted","revised","rebased","retried","cancelled","applied","rejected","review-returned"]},
            "effectDigest":nullable_digest.clone(),"authorityKind":{"enum":["caller","system","review"]},
            "systemApplyGrantRevision":nullable_digest,
            "turn":{"type":"string","enum":["party","official","nobody"]}}})
}

pub fn source_hooks(
    actions: &[crate::contract::ActionSource],
) -> impl Iterator<Item = (&str, &crate::contract::ProposalHookSource)> {
    actions.iter().flat_map(|action| {
        let hooks = match &action.execution {
            ActionExecutionSource::Proposal { proposal } => proposal.hooks.as_slice(),
            ActionExecutionSource::Immediate {} => &[],
        };
        hooks.iter().map(move |hook| (action.id.as_str(), hook))
    })
}

pub fn handler_source_path(handler: &HookHandlerSource) -> Option<&str> {
    match handler {
        HookHandlerSource::Rhai { script, .. } => Some(script),
        HookHandlerSource::Wasm { module, .. } => Some(module),
        HookHandlerSource::Url { .. } => None,
    }
}

pub(crate) fn compile_hooks(
    sources: &BTreeMap<String, CollectedActionSource>,
    actions: &mut CompiledActionInventory,
    assets: &[ModuleAssetSource],
) -> Result<(), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    for action in &mut actions.actions {
        let CompiledActionExecution::Proposal { proposal } = &mut action.execution else {
            continue;
        };
        let collected = &sources[&action.id];
        let ActionExecutionSource::Proposal { proposal: source } = &collected.source.execution
        else {
            unreachable!()
        };
        for hook in &source.hooks {
            let path = format!(
                "actions[id={}].execution.proposal.hooks[id={}]",
                action.id, hook.id
            );
            let (destination_id, handler) = match &hook.handler {
                HookHandlerSource::Url { destination_id } => {
                    if !crate::compiler::valid_logical_destination_id(destination_id) {
                        errors.push(Diagnostic::error(
                            "breg.event.hook-destination-invalid",
                            format!("{path}.handler.destinationId"),
                            "use a bounded logical destination identifier",
                        ));
                    }
                    (Some(destination_id.clone()), None)
                }
                local => {
                    let (source_path, abi, kind) = match local {
                        HookHandlerSource::Rhai { script, abi } => {
                            (script, abi, CompiledHookHandlerKind::Rhai)
                        }
                        HookHandlerSource::Wasm { module, abi } => {
                            (module, abi, CompiledHookHandlerKind::Wasm)
                        }
                        HookHandlerSource::Url { .. } => unreachable!(),
                    };
                    if abi.as_deref() != Some(HOOK_HANDLER_ABI_V1) {
                        errors.push(Diagnostic::error(
                            "breg.hook.handler-abi-unsupported",
                            format!("{path}.handler.abi"),
                            "use registry.hook-handler/v1",
                        ));
                    }
                    #[cfg(not(feature = "wasm"))]
                    if kind == CompiledHookHandlerKind::Wasm {
                        errors.push(Diagnostic::error(
                            "breg.hook.handler-wasm-build-unsupported",
                            format!("{path}.handler.type"),
                            "this compiler build does not admit WASM hook handlers",
                        ));
                        continue;
                    }
                    let Some(asset) = assets.iter().find(|asset| {
                        asset.module == collected.source_module && asset.path == *source_path
                    }) else {
                        errors.push(Diagnostic::error(
                            "breg.hook.handler-source-missing",
                            format!("{path}.handler"),
                            "supply the handler asset in its owning Action module",
                        ));
                        continue;
                    };
                    let start = errors.len();
                    match kind {
                        CompiledHookHandlerKind::Rhai => {
                            crate::compiler::validate_hook_script_asset(&asset.bytes, &mut errors)
                        }
                        CompiledHookHandlerKind::Wasm => {
                            crate::compiler::validate_hook_module_asset(&asset.bytes, &mut errors)
                        }
                    }
                    for error in &mut errors[start..] {
                        error.path = error.path.replace("recordTypes[].hooks[]", &path);
                    }
                    (
                        None,
                        Some(CompiledHookHandler {
                            kind,
                            abi: HOOK_HANDLER_ABI_V1.into(),
                            source_module: collected.source_module.clone(),
                            source_path: source_path.clone(),
                            digest: format!(
                                "sha256:{}",
                                crate::physical_names::hex_prefix(
                                    &Sha256::digest(&asset.bytes),
                                    32
                                )
                            ),
                            bytes: asset.bytes.clone(),
                        }),
                    )
                }
            };
            proposal.hooks.push(CompiledProposalHook {
                id: hook.id.clone(),
                display: hook.display.clone(),
                transitions: hook.transitions.iter().copied().collect(),
                destination_id,
                handler,
            });
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Re-derive every member of a native subscription's outbound authority.
pub(crate) fn compile_delivery(
    action: &CompiledAction,
    hook: &CompiledProposalHook,
) -> CompiledEventDelivery {
    let bytes = canonicalize_json(&proposal_event_schema())
        .expect("fixed Proposal event schema is canonical");
    CompiledEventDelivery {
        id: format!("events.proposals.{}.{}.webhook", action.id, hook.id),
        owner: CompiledEventOwner::ProposalAction {
            action: action.id.clone(),
        },
        event_id: hook.id.clone(),
        destination_id: hook.destination_id.clone(),
        handler: hook.handler.clone(),
        projection_fields: Vec::new(),
        when: None,
        principal: None,
        classification_ceiling: Classification::Internal,
        data_schema: PROPOSAL_EVENT_SCHEMA.into(),
        data_schema_fingerprint: format!(
            "sha256:{}",
            crate::physical_names::hex_prefix(&Sha256::digest(bytes), 32)
        ),
        data_schema_artifact_path: PROPOSAL_EVENT_SCHEMA_PATH.into(),
        authentication_profile: HookAuthenticationProfile::HmacSha256V1,
        delivery_mode: CompiledHookDeliveryMode::AfterCommit,
        retry_profile: CompiledHookRetryProfile::RegistryV1,
        attempt_timeout_ms: HOOK_ATTEMPT_TIMEOUT_MS,
        initial_backoff_ms: HOOK_INITIAL_BACKOFF_MS,
        maximum_backoff_ms: HOOK_MAXIMUM_BACKOFF_MS,
        exponential_backoff_multiplier: HOOK_BACKOFF_MULTIPLIER,
        maximum_attempts: HOOK_MAXIMUM_ATTEMPTS,
        retry_delays_ms: crate::compiler::hook_retry_delays(
            HOOK_INITIAL_BACKOFF_MS,
            HOOK_MAXIMUM_BACKOFF_MS,
            HOOK_MAXIMUM_ATTEMPTS,
        ),
        maximum_payload_bytes: MAX_PROPOSAL_EVENT_PAYLOAD_BYTES,
        dead_letter: HookDeadLetterMode::Required,
        operator_replay: true,
    }
}

#[cfg(feature = "runtime")]
pub(crate) fn exact_deliveries(
    registry: &CompiledRegistry,
    action: &CompiledAction,
) -> Result<Vec<CompiledEventDelivery>, crate::outbox::OutboxError> {
    use crate::outbox::OutboxError;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(OutboxError::Unavailable);
    };
    let expected = proposal
        .hooks
        .iter()
        .map(|hook| compile_delivery(action, hook))
        .collect::<Vec<_>>();
    let actual = registry.event_deliveries().deliveries.iter().filter(|delivery| matches!(&delivery.owner,CompiledEventOwner::ProposalAction{action:id} if id == &action.id)).collect::<Vec<_>>();
    if !exact_inventory(&expected, &actual) {
        return Err(OutboxError::Unavailable);
    }
    let mut ids = BTreeSet::new();
    if expected.iter().any(|delivery| {
        !ids.insert(&delivery.id) || delivery.destination_id.is_some() == delivery.handler.is_some()
    }) {
        return Err(OutboxError::Unavailable);
    }
    Ok(expected)
}

#[cfg(feature = "runtime")]
fn exact_inventory(expected: &[CompiledEventDelivery], actual: &[&CompiledEventDelivery]) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|delivery| {
            actual
                .iter()
                .copied()
                .filter(|actual| *actual == delivery)
                .count()
                == 1
        })
}

#[cfg(all(test, feature = "runtime"))]
#[path = "../tests/support/proposal_hooks_model.rs"]
mod test_model;

#[cfg(all(test, feature = "runtime"))]
#[test]
fn altered_native_delivery_authority_is_refused_by_exact_rederivation() {
    let source = test_model::source(json!([
        test_model::url_hook(),
        test_model::local_hook("local", json!([]))
    ]));
    let project =
        crate::contract::parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = crate::compiler::compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "hooks/local.rhai".into(),
            bytes: b"fn handle(ctx) { #{answer: \"none\"} }".to_vec(),
        }],
        crate::compiler::CompileProfile::Authoring,
    )
    .unwrap();
    let delivery = registry
        .event_deliveries()
        .deliveries
        .iter()
        .find(|entry| entry.destination_id.is_some())
        .unwrap();
    let expected = vec![delivery.clone()];
    assert!(exact_inventory(&expected, &[delivery]));
    let mutations: [fn(&mut CompiledEventDelivery); 7] = [
        |delivery| {
            delivery.owner = CompiledEventOwner::RecordType {
                record_type: "target".into(),
                trigger: crate::contract::EventTrigger::Created,
            }
        },
        |delivery| delivery.principal = Some("clerk".into()),
        |delivery| delivery.destination_id = Some("other".into()),
        |delivery| delivery.data_schema = "urn:substituted-schema".into(),
        |delivery| delivery.maximum_payload_bytes += 1,
        |delivery| delivery.maximum_attempts += 1,
        |delivery| delivery.projection_fields.push("value".into()),
    ];
    for mutate in mutations {
        let mut changed = delivery.clone();
        mutate(&mut changed);
        assert!(!exact_inventory(&expected, &[&changed]));
    }
    assert!(!exact_inventory(&expected, &[]));
    assert!(!exact_inventory(&expected, &[delivery, delivery]));
}

pub fn matching_transitions(
    transitions: &BTreeSet<ProposalEventTransition>,
) -> impl Iterator<Item = ProposalEventTransition> + '_ {
    [
        ProposalEventTransition::Started,
        ProposalEventTransition::Edited,
        ProposalEventTransition::Submitted,
        ProposalEventTransition::Revised,
        ProposalEventTransition::Rebased,
        ProposalEventTransition::Retried,
        ProposalEventTransition::Cancelled,
        ProposalEventTransition::Applied,
        ProposalEventTransition::Rejected,
        ProposalEventTransition::ReviewReturned,
    ]
    .into_iter()
    .filter(|transition| transitions.is_empty() || transitions.contains(transition))
}
