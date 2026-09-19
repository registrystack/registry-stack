// SPDX-License-Identifier: Apache-2.0
//! The BREG-owned proposed action outcome: the backend-neutral value tree a
//! handler backend's result decodes into, and the one validator that turns a
//! proposed outcome into an accepted effect plan or a declared refusal.
//!
//! Decoding is separate from validation on purpose. A decode layer turns one
//! backend's representation into [`ProposedValue`] and then
//! [`ProposedActionOutcome`], performing only the checks that precede every
//! product decision: document shape, member sets, string kinds. Everything
//! that consults the compiled action, the slot catalogue, the write ceilings,
//! the reference envelopes, the mutation bounds, the ordering and the
//! snapshot size, happens once, in [`validate_proposed_outcome`], for every
//! backend. The Rhai evaluation path routes through the same two steps it
//! always took, with the same diagnostics in the same order.
//!
//! The WASM outcome-byte decoder is compiled behind the `wasm` cargo
//! feature, on by default, and serves the WASM execution path in
//! those builds (and the parity tests beside it).

use std::collections::BTreeSet;

use rhai::{Array, Dynamic, ImmutableString, Map};
use serde_json::{Map as JsonMap, Number, Value};

use crate::action_handler::{
    ActionHandlerDiagnostic, ActionHandlerError, ActionHandlerOutcome, ActionHandlerRefusal,
};
use crate::contract::{FieldTypeSource, Operation};
use crate::data::{validate_field_value, FieldValue};
use crate::model::{
    CompiledAction, CompiledActionEffect, CompiledActionHandler, CompiledActionMutation,
    CompiledActionValue, CompiledChangeRequestPlannerWrite,
};
use crate::rhai_planner::{
    self, CandidateChangeRequestEffect, CandidateChangeRequestMutation,
    CandidateChangeRequestTarget, CandidateChangeRequestTargetBinding, CandidateChangeRequestValue,
    ChangeRequestPlannerError,
};

/// The backend-neutral value tree of a handler outcome document.
///
/// Both backends' representations map here totally: decoding never fails
/// because of a value's kind, so a refusal always names the position and the
/// rule that broke, exactly as the Rhai decode always has. `Inexpressible`
/// collapses the kinds no backend may plan with, such as Rhai floats and
/// characters and JSON numbers outside i64; the validator refuses them at
/// the same points with the same messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProposedValue {
    /// JSON null and the Rhai unit value: present, but not a plannable value.
    Absent,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<ProposedValue>),
    /// Object members in the backend's own iteration order; both current
    /// representations iterate members sorted by name.
    Object(Vec<(String, ProposedValue)>),
    Inexpressible,
}

/// An outcome proposal with its document shape settled: one exclusive arm,
/// its top-level members validated, and its identifying strings decoded. The
/// remaining checks all consult the compiled action, so they run once in the
/// shared validator for every backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProposedActionOutcome {
    Refusal {
        code: String,
        /// The raw `field` member: whether it is a declared input ID is a
        /// product decision, checked after the refusal catalogue.
        field: Option<ProposedValue>,
    },
    Effects {
        /// The raw effect entries; each entry's shape is checked against its
        /// declared slot in validator order.
        effects: Vec<ProposedValue>,
    },
}

/// Decode a Rhai handler result into the neutral outcome document. Total by
/// construction: every Rhai kind either maps to a proposal value or becomes
/// `Inexpressible`, which the validator refuses where the Rhai decode path
/// refused the kind. The decode recurses, so a handler result passes
/// [`bound_rhai_result`] first.
pub(crate) fn rhai_document(value: Dynamic) -> ProposedValue {
    if value.is_unit() {
        return ProposedValue::Absent;
    }
    if value.is::<bool>() {
        return ProposedValue::Bool(value.cast::<bool>());
    }
    if value.is::<rhai::INT>() {
        return ProposedValue::Int(value.cast::<rhai::INT>());
    }
    if value.is::<ImmutableString>() {
        return ProposedValue::Str(value.cast::<ImmutableString>().to_string());
    }
    if value.is::<Array>() {
        return ProposedValue::Array(
            value
                .cast::<Array>()
                .into_iter()
                .map(rhai_document)
                .collect(),
        );
    }
    if value.is::<Map>() {
        return ProposedValue::Object(
            value
                .cast::<Map>()
                .into_iter()
                .map(|(key, value)| (key.to_string(), rhai_document(value)))
                .collect(),
        );
    }
    ProposedValue::Inexpressible
}

/// Decode parsed outcome JSON into the neutral outcome document. Total for
/// the same reason as [`rhai_document`]: JSON numbers outside i64 decode to
/// `Inexpressible` rather than failing the parse.
#[cfg(any(feature = "runtime", feature = "wasm"))]
pub(crate) fn json_document(value: Value) -> ProposedValue {
    match value {
        Value::Null => ProposedValue::Absent,
        Value::Bool(value) => ProposedValue::Bool(value),
        Value::Number(value) => value
            .as_i64()
            .map(ProposedValue::Int)
            .unwrap_or(ProposedValue::Inexpressible),
        Value::String(value) => ProposedValue::Str(value),
        Value::Array(values) => {
            ProposedValue::Array(values.into_iter().map(json_document).collect())
        }
        Value::Object(members) => ProposedValue::Object(
            members
                .into_iter()
                .map(|(key, value)| (key, json_document(value)))
                .collect(),
        ),
    }
}

/// Decode a WASM handler's outcome bytes into a proposal: reject repeated
/// JSON members while parsing, then run the same shared output bound and
/// document decode the Rhai path runs. Compiled under the `wasm` feature
/// and used by the WASM execution path in those builds.
#[cfg(feature = "wasm")]
pub(crate) fn decode_wasm_outcome(
    bytes: &[u8],
    maximum_snapshot_bytes: u32,
) -> Result<ProposedActionOutcome, ActionHandlerDiagnostic> {
    let value = registry_platform_script::json_check::check_no_duplicate_members(bytes).map_err(
        |error| {
            let message = if error.duplicate_path().is_some() {
                "Return the handler outcome as a JSON object without duplicate members."
            } else {
                "Return the handler outcome as a valid JSON document."
            };
            ActionHandlerDiagnostic::new(ActionHandlerError::Result, message)
        },
    )?;
    let document = json_document(value);
    bound_document(&document, maximum_snapshot_bytes)?;
    decode_document(document)
}

/// The shared output bound applied to a Rhai handler result while it is
/// still a Rhai value. Decoding a Rhai value into the neutral document
/// recurses to build it, so the depth ceiling is checked here, before the
/// decode descends: a result nested past
/// [`rhai_planner::MAXIMUM_VALUE_DEPTH`] is refused without either walk
/// reaching its bottom. Every charge and ceiling matches [`bound_document`],
/// which the decoded document then passes through with every other backend's
/// outcome.
pub(crate) fn bound_rhai_result(
    value: &Dynamic,
    maximum_snapshot_bytes: u32,
) -> Result<(), ActionHandlerError> {
    let mut remaining = maximum_snapshot_bytes as usize;
    bound_rhai_value(value, 0, &mut remaining)
}

fn bound_rhai_value(
    value: &Dynamic,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ActionHandlerError> {
    if depth > rhai_planner::MAXIMUM_VALUE_DEPTH {
        return Err(ActionHandlerError::Resource);
    }
    *remaining = remaining
        .checked_sub(8)
        .ok_or(ActionHandlerError::Resource)?;
    if let Some(text) = value.read_lock::<ImmutableString>() {
        *remaining = remaining
            .checked_sub(text.len())
            .ok_or(ActionHandlerError::Resource)?;
    } else if let Some(items) = value.read_lock::<Array>() {
        if items.len() > rhai_planner::MAXIMUM_ARRAY_ITEMS {
            return Err(ActionHandlerError::Resource);
        }
        for item in items.iter() {
            bound_rhai_value(item, depth + 1, remaining)?;
        }
    } else if let Some(members) = value.read_lock::<Map>() {
        if members.len() > rhai_planner::MAXIMUM_MAP_ENTRIES {
            return Err(ActionHandlerError::Resource);
        }
        for (key, item) in members.iter() {
            *remaining = remaining
                .checked_sub(key.len())
                .ok_or(ActionHandlerError::Resource)?;
            bound_rhai_value(item, depth + 1, remaining)?;
        }
    }
    Ok(())
}

/// The shared output bound every backend's outcome must fit inside before it
/// is decoded: the value-depth, per-value, string, array and map ceilings
/// charged against the action's snapshot budget. The same bound, whatever
/// representation the backend produced.
pub(crate) fn bound_document(
    document: &ProposedValue,
    maximum_snapshot_bytes: u32,
) -> Result<(), ActionHandlerError> {
    let mut remaining = maximum_snapshot_bytes as usize;
    bound_value(document, 0, &mut remaining)
}

fn bound_value(
    value: &ProposedValue,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ActionHandlerError> {
    if depth > rhai_planner::MAXIMUM_VALUE_DEPTH {
        return Err(ActionHandlerError::Resource);
    }
    *remaining = remaining
        .checked_sub(8)
        .ok_or(ActionHandlerError::Resource)?;
    match value {
        ProposedValue::Str(text) => {
            *remaining = remaining
                .checked_sub(text.len())
                .ok_or(ActionHandlerError::Resource)?;
        }
        ProposedValue::Array(items) => {
            if items.len() > rhai_planner::MAXIMUM_ARRAY_ITEMS {
                return Err(ActionHandlerError::Resource);
            }
            for item in items {
                bound_value(item, depth + 1, remaining)?;
            }
        }
        ProposedValue::Object(members) => {
            if members.len() > rhai_planner::MAXIMUM_MAP_ENTRIES {
                return Err(ActionHandlerError::Resource);
            }
            for (key, item) in members {
                *remaining = remaining
                    .checked_sub(key.len())
                    .ok_or(ActionHandlerError::Resource)?;
                bound_value(item, depth + 1, remaining)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Settle the document shape of a proposal: the top-level map, the exclusive
/// effects-or-refusal arms, and the member sets and identifying strings that
/// precede every product decision.
pub(crate) fn decode_document(
    document: ProposedValue,
) -> Result<ProposedActionOutcome, ActionHandlerDiagnostic> {
    let members = match document {
        ProposedValue::Object(members) => members,
        _ => {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Return a map containing either effects or refusal.",
            ))
        }
    };
    if member(&members, "effects").is_some() && member(&members, "refusal").is_some() {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "Return either effects or refusal, never both.",
        ));
    }
    if let Some(refusal) = member(&members, "refusal") {
        if !exact_members(&members, &["refusal"], &[]) {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "A refusal outcome may contain only refusal.",
            ));
        }
        let refusal_members = match refusal {
            ProposedValue::Object(refusal_members) => refusal_members,
            _ => {
                return Err(ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Return refusal as a map with code and an optional field.",
                ))
            }
        };
        if !exact_members(refusal_members, &["code"], &["field"]) {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "A refusal requires code and may contain only an optional field; declare its label in the handler catalogue.",
            ));
        }
        let code = match member(refusal_members, "code") {
            Some(value) => member_string(value).map_err(|_| {
                ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Use a string code from the handler's declared refusal catalogue.",
                )
            })?,
            None => {
                return Err(ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Use a string code from the handler's declared refusal catalogue.",
                ))
            }
        };
        let field = member(refusal_members, "field").cloned();
        return Ok(ProposedActionOutcome::Refusal { code, field });
    }
    if !exact_members(&members, &["effects"], &[]) {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "An effects outcome must contain only effects.",
        ));
    }
    let effects = match member(&members, "effects") {
        Some(ProposedValue::Array(effects)) => effects.clone(),
        _ => {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Return effects as a non-empty list of declared write slots.",
            ))
        }
    };
    Ok(ProposedActionOutcome::Effects { effects })
}

/// The one shared validator: accept a proposal against the compiled action
/// or refuse it with the diagnostic the Rhai path has always produced. Every
/// remaining check lives here, in its established order: the refusal
/// catalogue and input IDs, the write-slot catalogue and target ceiling, the
/// per-slot mutation ceilings and reference envelopes, the field-mutation
/// ceiling, the fromEffect wiring, dependency ordering, the final effect
/// mapping and the serialized snapshot size.
pub(crate) fn validate_proposed_outcome(
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    proposed: ProposedActionOutcome,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    match proposed {
        ProposedActionOutcome::Refusal { code, field } => {
            let label = handler.refusals.get(&code).cloned().ok_or_else(|| {
                ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Use a code from the handler's declared refusal catalogue.",
                )
            })?;
            let field = field
                .map(|value| member_string(&value))
                .transpose()
                .map_err(|_| {
                    ActionHandlerDiagnostic::new(
                        ActionHandlerError::Result,
                        "Use a declared input ID as the refusal field, or omit field.",
                    )
                })?;
            if field
                .as_ref()
                .is_some_and(|field| !action.inputs.iter().any(|input| &input.id == field))
            {
                return Err(ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Use a declared input ID as the refusal field, or omit field.",
                ));
            }
            Ok(ActionHandlerOutcome::Refusal(ActionHandlerRefusal {
                code,
                label,
                field,
            }))
        }
        ProposedActionOutcome::Effects { effects } => {
            validate_proposed_effects(action, handler, effects)
        }
    }
}

fn validate_proposed_effects(
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    results: Vec<ProposedValue>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    if results.is_empty() {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Ceiling,
            "Emit at least one declared write slot, or return a declared refusal.",
        ));
    }
    if results.len() > usize::from(action.maximum_targets) {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Ceiling,
            "Emit no more effects than the action's target bound.",
        ));
    }
    let mut effects = Vec::new();
    let mut selected = BTreeSet::new();
    for result in &results {
        let effect = match result {
            ProposedValue::Object(effect) => effect,
            _ => {
                return Err(ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Return each effect as a map with id and set or clear.",
                ))
            }
        };
        let id = match member(effect, "id") {
            None => {
                return Err(ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Give each effect an id from the handler's declared write slots.",
                ))
            }
            Some(value) => member_string(value).map_err(|_| {
                ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Use a string id from the handler's declared write slots.",
                )
            })?,
        };
        let slot =
            handler
                .writes
                .iter()
                .find(|slot| slot.id == id)
                .ok_or(ActionHandlerDiagnostic {
                    kind: ActionHandlerError::Ceiling,
                    evidence_capability: None,
                    slot: None,
                    field: None,
                    message: "Use an id from the handler's declared write slots.",
                })?;
        if !exact_members(effect, &["id"], &["set", "clear"]) {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "An effect may contain only id, set and clear; the declared slot fixes its target and operation.",
            )
            .at_slot(slot));
        }
        if !selected.insert(id.clone()) {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Emit each declared write slot at most once.",
            )
            .at_slot(slot));
        }
        let mutations = decode_slot_mutations(&slot.ceiling, effect).map_err(|diagnostic| {
            ActionHandlerDiagnostic {
                kind: diagnostic.kind.into(),
                evidence_capability: None,
                slot: Some(slot.id.clone()),
                field: diagnostic.field,
                message: diagnostic.message,
            }
        })?;
        let depends_on = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                CandidateChangeRequestMutation::Set {
                    value: CandidateChangeRequestValue::FromEffect { effect, .. },
                    ..
                } => Some(effect.clone()),
                _ => None,
            })
            .collect();
        let binding = match &slot.ceiling.target_from_field {
            Some(from_field) => CandidateChangeRequestTargetBinding::Existing {
                from_field: from_field.clone(),
            },
            None => CandidateChangeRequestTargetBinding::ReservedCreate { effect: id.clone() },
        };
        effects.push(CandidateChangeRequestEffect {
            id,
            target: CandidateChangeRequestTarget {
                entity_id: slot.ceiling.target_entity_id.clone(),
                binding,
            },
            operation: slot.ceiling.operation,
            mutations,
            depends_on,
        });
    }
    if effects
        .iter()
        .map(|effect| effect.mutations.len())
        .sum::<usize>()
        > usize::from(action.maximum_field_mutations)
    {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Ceiling,
            "Emit no more field mutations than the action's field-mutation bound.",
        ));
    }
    for effect in &effects {
        for mutation in &effect.mutations {
            if let CandidateChangeRequestMutation::Set {
                field,
                value:
                    CandidateChangeRequestValue::FromEffect {
                        effect: id,
                        target_entity_id,
                    },
            } = mutation
            {
                let diagnostic = |kind, message| ActionHandlerDiagnostic {
                    kind,
                    evidence_capability: None,
                    slot: Some(effect.id.clone()),
                    field: Some(field.clone()),
                    message,
                };
                let source = effects
                    .iter()
                    .find(|effect| &effect.id == id)
                    .ok_or_else(|| {
                        diagnostic(
                            ActionHandlerError::Result,
                            "Emit the create slot named by fromEffect in the same outcome.",
                        )
                    })?;
                if source.operation != Operation::Create
                    || &source.target.entity_id != target_entity_id
                {
                    return Err(diagnostic(
                        ActionHandlerError::Ceiling,
                        "Use fromEffect only with an emitted create slot for the field's reference target.",
                    ));
                }
            }
        }
    }
    let effects = rhai_planner::order_candidates(effects)
        .map_err(|kind| {
            ActionHandlerDiagnostic::new(
                kind.into(),
                "Emit create references without a dependency cycle.",
            )
        })?
        .into_iter()
        .map(|effect| {
            let slot = action
                .effects
                .iter()
                .find(|slot| slot.id == effect.id)
                .ok_or(ActionHandlerError::Ceiling)?;
            let mutations = effect
                .mutations
                .into_iter()
                .map(|mutation| match mutation {
                    CandidateChangeRequestMutation::Clear { field } => {
                        CompiledActionMutation::Clear { field }
                    }
                    CandidateChangeRequestMutation::Set { field, value } => {
                        CompiledActionMutation::Set {
                            field,
                            value: match value {
                                CandidateChangeRequestValue::Literal(value) => {
                                    CompiledActionValue::Literal { value }
                                }
                                CandidateChangeRequestValue::FromRequestField { field: input } => {
                                    CompiledActionValue::FromInput { input }
                                }
                                CandidateChangeRequestValue::FromEffect {
                                    effect,
                                    target_entity_id,
                                } => CompiledActionValue::FromEffect {
                                    effect,
                                    target_entity_id,
                                },
                            },
                        }
                    }
                })
                .collect();
            Ok(CompiledActionEffect {
                id: effect.id,
                target: slot.target.clone(),
                operation: slot.operation,
                mutations,
                depends_on: effect.depends_on,
            })
        })
        .collect::<Result<Vec<_>, ActionHandlerError>>()?;
    if serde_json::to_vec(&effects)
        .map_err(|_| ActionHandlerError::Result)?
        .len()
        > action.maximum_snapshot_bytes as usize
    {
        return Err(ActionHandlerError::Resource.into());
    }
    Ok(ActionHandlerOutcome::Effects(effects))
}

/// The mutation diagnostic shared by the action validator and the
/// change-request planner: a closed kind, a compiled field location, and a
/// static repair message. Locations come from the compiled ceiling, never an
/// unknown script key.
pub(crate) struct WriteMutationDiagnostic {
    pub kind: ChangeRequestPlannerError,
    pub field: Option<String>,
    pub message: &'static str,
}

impl WriteMutationDiagnostic {
    fn new(kind: ChangeRequestPlannerError, message: &'static str) -> Self {
        Self {
            kind,
            field: None,
            message,
        }
    }

    fn at_field(
        write: &CompiledChangeRequestPlannerWrite,
        field: &str,
        kind: ChangeRequestPlannerError,
        message: &'static str,
    ) -> Self {
        Self {
            kind,
            field: write.fields.get(field).cloned(),
            message,
        }
    }
}

/// Decode one effect's set and clear members into candidate mutations
/// against the slot's compiled write ceiling. Shared by the action validator
/// and the change-request planner, so both enforce the same field, ceiling
/// and reference rules with the same diagnostics.
pub(crate) fn decode_slot_mutations(
    write: &CompiledChangeRequestPlannerWrite,
    members: &[(String, ProposedValue)],
) -> Result<Vec<CandidateChangeRequestMutation>, WriteMutationDiagnostic> {
    let operation = write.operation;
    let mut mutations = Vec::new();
    let mut touched = BTreeSet::new();
    if let Some(set) = member(members, "set") {
        let set_members = match set {
            ProposedValue::Object(set_members) => set_members,
            _ => {
                return Err(WriteMutationDiagnostic::new(
                    ChangeRequestPlannerError::Result,
                    "Return set as a map of declared fields to values.",
                ))
            }
        };
        for (field, value) in set_members {
            if !write.fields.contains(field.as_str()) {
                return Err(WriteMutationDiagnostic::at_field(
                    write,
                    field,
                    ChangeRequestPlannerError::Ceiling,
                    "Set only fields declared by this slot.",
                ));
            }
            touched.insert(field.to_string());
            mutations.push(CandidateChangeRequestMutation::Set {
                field: field.to_string(),
                value: decode_slot_value(write, field, value).map_err(|kind| {
                    let message = if matches!(value, ProposedValue::Absent) {
                        "Set a non-null value; use clear only for optional patch fields."
                    } else if matches!(
                        write.field_types.get(field.as_str()),
                        Some(FieldTypeSource::Reference { .. })
                    ) {
                        "Use a declared fromField or an emitted compatible fromEffect reference."
                    } else {
                        "Use a value matching the declared field type and bounds."
                    };
                    WriteMutationDiagnostic::at_field(write, field, kind, message)
                })?,
            });
        }
    }
    if let Some(clear) = member(members, "clear") {
        let clear_items = match clear {
            ProposedValue::Array(clear_items) => clear_items,
            _ => {
                return Err(WriteMutationDiagnostic::new(
                    ChangeRequestPlannerError::Result,
                    "Return clear as a list of optional patch field names.",
                ))
            }
        };
        for item in clear_items {
            let field = member_string(item).map_err(|kind| {
                WriteMutationDiagnostic::new(kind, "Use declared field names in clear.")
            })?;
            let message = if !write.fields.contains(&field) {
                Some("Clear only fields declared by this slot.")
            } else if operation == Operation::Create {
                Some("Create effects cannot clear fields; omit optional fields or set a value.")
            } else if write.required_fields.contains(&field) {
                Some("Set a value for this required field; it cannot be cleared.")
            } else if !touched.insert(field.clone()) {
                Some("Write each field once, using either set or clear.")
            } else {
                None
            };
            if let Some(message) = message {
                return Err(WriteMutationDiagnostic::at_field(
                    write,
                    &field,
                    ChangeRequestPlannerError::Ceiling,
                    message,
                ));
            }
            mutations.push(CandidateChangeRequestMutation::Clear { field });
        }
    }
    if mutations.is_empty() {
        return Err(WriteMutationDiagnostic::new(
            ChangeRequestPlannerError::Result,
            "Return at least one set or clear mutation for the slot.",
        ));
    }
    if operation == Operation::Create {
        if let Some(field) = write.required_fields.difference(&touched).next() {
            return Err(WriteMutationDiagnostic::at_field(
                write,
                field,
                ChangeRequestPlannerError::Ceiling,
                "Set this required field when creating a record.",
            ));
        }
    }
    Ok(mutations)
}

fn decode_slot_value(
    write: &CompiledChangeRequestPlannerWrite,
    field: &str,
    value: &ProposedValue,
) -> Result<CandidateChangeRequestValue, ChangeRequestPlannerError> {
    let field_type = write
        .field_types
        .get(field)
        .ok_or(ChangeRequestPlannerError::Ceiling)?;
    if let FieldTypeSource::Reference { .. } = field_type {
        let sources = write
            .reference_sources
            .get(field)
            .ok_or(ChangeRequestPlannerError::Ceiling)?;
        let envelope = match value {
            ProposedValue::Object(envelope) => envelope,
            _ => return Err(ChangeRequestPlannerError::Result),
        };
        match (
            member(envelope, "fromField"),
            member(envelope, "fromEffect"),
        ) {
            (Some(field), None) => {
                if !exact_members(envelope, &["fromField"], &[]) {
                    return Err(ChangeRequestPlannerError::Result);
                }
                let field = member_string(field)?;
                if !sources.request_fields.contains(&field) {
                    return Err(ChangeRequestPlannerError::Ceiling);
                }
                Ok(CandidateChangeRequestValue::FromRequestField { field })
            }
            (None, Some(effect)) => {
                if !exact_members(envelope, &["fromEffect"], &[]) {
                    return Err(ChangeRequestPlannerError::Result);
                }
                let effect = member_string(effect)?;
                let target_entity_id = sources
                    .create_entities
                    .iter()
                    .next()
                    .cloned()
                    .ok_or(ChangeRequestPlannerError::Ceiling)?;
                Ok(CandidateChangeRequestValue::FromEffect {
                    effect,
                    target_entity_id,
                })
            }
            _ => Err(ChangeRequestPlannerError::Result),
        }
    } else {
        let value = proposed_to_json(value, 0)?;
        if value.is_null() || !validate_field_value(FieldValue::Json(&value), field_type) {
            return Err(ChangeRequestPlannerError::Result);
        }
        Ok(CandidateChangeRequestValue::Literal(value))
    }
}

fn proposed_to_json(
    value: &ProposedValue,
    depth: usize,
) -> Result<Value, ChangeRequestPlannerError> {
    if depth > rhai_planner::MAXIMUM_VALUE_DEPTH {
        return Err(ChangeRequestPlannerError::Resource);
    }
    match value {
        ProposedValue::Absent => Ok(Value::Null),
        ProposedValue::Bool(value) => Ok(Value::Bool(*value)),
        ProposedValue::Int(value) => Ok(Value::Number(Number::from(*value))),
        ProposedValue::Str(value) => {
            if value.len() > rhai_planner::MAXIMUM_STRING_BYTES {
                return Err(ChangeRequestPlannerError::Resource);
            }
            Ok(Value::String(value.clone()))
        }
        ProposedValue::Array(items) => {
            if items.len() > rhai_planner::MAXIMUM_ARRAY_ITEMS {
                return Err(ChangeRequestPlannerError::Resource);
            }
            items
                .iter()
                .map(|value| proposed_to_json(value, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        ProposedValue::Object(members) => {
            if members.len() > rhai_planner::MAXIMUM_MAP_ENTRIES {
                return Err(ChangeRequestPlannerError::Resource);
            }
            members
                .iter()
                .map(|(key, value)| {
                    if key.len() > rhai_planner::MAXIMUM_STRING_BYTES {
                        return Err(ChangeRequestPlannerError::Resource);
                    }
                    Ok((key.clone(), proposed_to_json(value, depth + 1)?))
                })
                .collect::<Result<JsonMap<_, _>, _>>()
                .map(Value::Object)
        }
        ProposedValue::Inexpressible => Err(ChangeRequestPlannerError::Result),
    }
}

fn member<'a>(members: &'a [(String, ProposedValue)], name: &str) -> Option<&'a ProposedValue> {
    members
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn exact_members(
    members: &[(String, ProposedValue)],
    required: &[&str],
    optional: &[&str],
) -> bool {
    required.iter().all(|key| member(members, key).is_some())
        && members
            .iter()
            .all(|(key, _)| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn member_string(value: &ProposedValue) -> Result<String, ChangeRequestPlannerError> {
    match value {
        ProposedValue::Str(value) if value.len() <= rhai_planner::MAXIMUM_STRING_BYTES => {
            Ok(value.clone())
        }
        _ => Err(ChangeRequestPlannerError::Result),
    }
}

#[cfg(test)]
#[path = "tests/action_outcome_rhai_bound_tests.rs"]
mod action_outcome_rhai_bound_tests;

#[cfg(all(test, feature = "wasm"))]
#[path = "tests/action_outcome_wasm_parity_tests.rs"]
mod action_outcome_wasm_parity_tests;
