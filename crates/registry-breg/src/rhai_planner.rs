// SPDX-License-Identifier: Apache-2.0

//! Closed, bounded Rhai kernel for change-request effect planning.

use std::{collections::BTreeSet, time::Instant};

#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicUsize, Ordering};

use registry_platform_script::rhai as platform;
use rhai::{Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position, AST};
use serde_json::{Map as JsonMap, Value};

use crate::{
    contract::{Operation, CHANGE_REQUEST_PLAN_ABI_V1},
    model::{
        CompiledChangeRequest, CompiledChangeRequestMutation, CompiledChangeRequestPlanner,
        CompiledChangeRequestPlannerWrite, CompiledChangeRequestTargetBinding,
        CompiledChangeRequestValue,
    },
};

pub const MAXIMUM_OPERATIONS: u64 = 100_000;
pub const MAXIMUM_CALL_DEPTH: usize = 32;
pub const MAXIMUM_EXPRESSION_DEPTH: usize = 64;
pub const MAXIMUM_SOURCE_BYTES: usize = 65_536;
pub const MAXIMUM_STRING_BYTES: usize = 16_384;
pub const MAXIMUM_ARRAY_ITEMS: usize = 256;
pub const MAXIMUM_MAP_ENTRIES: usize = 256;
pub const MAXIMUM_VALUE_DEPTH: usize = 64;

/// The bounded Rhai execution profile every planner and handler evaluation
/// runs under: the constants above, applied by the platform script adapter.
/// The `join` helper registration and the per-call deadline wiring are added
/// by `engine` below; every other setting is exactly this profile.
const SCRIPT_PROFILE: platform::RhaiProfile = platform::RhaiProfile {
    limits: platform::RhaiLimits {
        operations: MAXIMUM_OPERATIONS,
        call_levels: MAXIMUM_CALL_DEPTH,
        expression_depth: MAXIMUM_EXPRESSION_DEPTH,
        modules: 0,
        string_bytes: MAXIMUM_STRING_BYTES,
        array_items: MAXIMUM_ARRAY_ITEMS,
        map_entries: MAXIMUM_MAP_ENTRIES,
    },
    base: platform::RhaiBaseEngine::Standard,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: MAXIMUM_SOURCE_BYTES,
};

#[cfg(feature = "postgres-test")]
static TEST_PLANNER_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "postgres-test")]
pub fn reset_test_planner_invocation_count() {
    TEST_PLANNER_INVOCATIONS.store(0, Ordering::Relaxed);
}

#[cfg(feature = "postgres-test")]
pub fn test_planner_invocation_count() -> usize {
    TEST_PLANNER_INVOCATIONS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeRequestPlannerError {
    Source,
    Entrypoint,
    Execution,
    Result,
    Ceiling,
    Resource,
    Deadline,
}

impl ChangeRequestPlannerError {
    /// The closed kinds a submission is refused for. A planner that exhausted
    /// its time budget is absent: it is a service outage, not a refusal.
    pub const PLAN_REFUSALS: [Self; 6] = [
        Self::Source,
        Self::Entrypoint,
        Self::Execution,
        Self::Result,
        Self::Ceiling,
        Self::Resource,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Source => "change_request.planner.source",
            Self::Entrypoint => "change_request.planner.entrypoint",
            Self::Execution => "change_request.planner.execution",
            Self::Result => "change_request.planner.result",
            Self::Ceiling => "change_request.planner.ceiling",
            Self::Resource => "change_request.planner.resource",
            Self::Deadline => "change_request.planner.deadline",
        }
    }

    /// The exact problem detail the service answers for this failure.
    ///
    /// A refusal names the failure kind from the closed vocabulary and nothing
    /// else: no script text, no request value, no target data. A planner that
    /// ran out of time is an outage rather than a refusal, so it carries the
    /// unavailable detail every other timeout carries.
    pub const fn problem_detail(self) -> &'static str {
        match self {
            Self::Source => {
                "The change-request planner refused the submission: change_request.planner.source."
            }
            Self::Entrypoint => {
                "The change-request planner refused the submission: change_request.planner.entrypoint."
            }
            Self::Execution => {
                "The change-request planner refused the submission: change_request.planner.execution."
            }
            Self::Result => {
                "The change-request planner refused the submission: change_request.planner.result."
            }
            Self::Ceiling => {
                "The change-request planner refused the submission: change_request.planner.ceiling."
            }
            Self::Resource => {
                "The change-request planner refused the submission: change_request.planner.resource."
            }
            Self::Deadline => "The Registry mutation service is unavailable.",
        }
    }
}

impl std::fmt::Display for ChangeRequestPlannerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ChangeRequestPlannerError {}

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledEffectPlanCandidate {
    pub effects: Vec<CandidateChangeRequestEffect>,
    pub planner_binding: CandidatePlannerBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePlannerBinding {
    pub kind: &'static str,
    pub abi_identifier: String,
    pub script_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateChangeRequestEffect {
    pub id: String,
    pub target: CandidateChangeRequestTarget,
    pub operation: Operation,
    pub mutations: Vec<CandidateChangeRequestMutation>,
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateChangeRequestTarget {
    pub entity_id: String,
    pub binding: CandidateChangeRequestTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateChangeRequestTargetBinding {
    Existing { from_field: String },
    ReservedCreate { effect: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum CandidateChangeRequestMutation {
    Set {
        field: String,
        value: CandidateChangeRequestValue,
    },
    Clear {
        field: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum CandidateChangeRequestValue {
    Literal(Value),
    FromRequestField {
        field: String,
    },
    FromEffect {
        effect: String,
        target_entity_id: String,
    },
}

pub struct ChangeRequestPlannerRuntime;

impl ChangeRequestPlannerRuntime {
    pub fn compile_source(source: &str) -> Result<AST, ChangeRequestPlannerError> {
        compile_entrypoint(source, "plan")
    }
}

pub(crate) fn compile_entrypoint(
    source: &str,
    entrypoint: &str,
) -> Result<AST, ChangeRequestPlannerError> {
    compile_entrypoint_detailed(source, entrypoint).map_err(|error| match error {
        EntrypointCompileError::SourceBound | EntrypointCompileError::Parse(_) => {
            ChangeRequestPlannerError::Source
        }
        EntrypointCompileError::Entrypoint => ChangeRequestPlannerError::Entrypoint,
    })
}

pub(crate) enum EntrypointCompileError {
    SourceBound,
    Parse(rhai::Position),
    Entrypoint,
}

pub(crate) fn compile_entrypoint_detailed(
    source: &str,
    entrypoint: &str,
) -> Result<AST, EntrypointCompileError> {
    platform::compile_entrypoint(&SCRIPT_PROFILE, source, entrypoint, &[1]).map_err(|error| {
        match error {
            platform::RhaiCompileError::SourceBound => EntrypointCompileError::SourceBound,
            platform::RhaiCompileError::Parse(position) => EntrypointCompileError::Parse(position),
            platform::RhaiCompileError::Entrypoint => EntrypointCompileError::Entrypoint,
        }
    })
}

pub fn plan_change_request_effects(
    plan: &CompiledChangeRequest,
    request_fields: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<CompiledEffectPlanCandidate, ChangeRequestPlannerError> {
    let Some(planner) = plan.planner.as_ref() else {
        return declarative_candidate(plan, request_fields);
    };
    if planner.script_bytes.len() > MAXIMUM_SOURCE_BYTES {
        return Err(ChangeRequestPlannerError::Source);
    }
    let source = std::str::from_utf8(&planner.script_bytes)
        .map_err(|_| ChangeRequestPlannerError::Source)?;
    if Instant::now() >= deadline {
        return Err(ChangeRequestPlannerError::Deadline);
    }
    let engine = engine(Some(deadline));
    let ast = ChangeRequestPlannerRuntime::compile_source(source)?;
    let ctx = planner_context(planner, request_fields)?;
    #[cfg(feature = "postgres-test")]
    TEST_PLANNER_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let result =
        platform::call_with_fresh_scope(&engine, &ast, "plan", (ctx,)).map_err(|error| {
            if Instant::now() >= deadline {
                ChangeRequestPlannerError::Deadline
            } else if platform::classify_failure(&error)
                == platform::RhaiFailureCategory::ResourceExhausted
            {
                ChangeRequestPlannerError::Resource
            } else {
                ChangeRequestPlannerError::Execution
            }
        })?;
    decode_plan(plan, planner, result)
}

fn declarative_candidate(
    plan: &CompiledChangeRequest,
    _request_fields: &JsonMap<String, Value>,
) -> Result<CompiledEffectPlanCandidate, ChangeRequestPlannerError> {
    let effects = plan
        .effects
        .iter()
        .map(|effect| {
            let binding = match &effect.target.binding {
                CompiledChangeRequestTargetBinding::Existing { from_field } => {
                    CandidateChangeRequestTargetBinding::Existing {
                        from_field: from_field.clone(),
                    }
                }
                CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
                    CandidateChangeRequestTargetBinding::ReservedCreate {
                        effect: effect.clone(),
                    }
                }
            };
            let mutations = effect
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    CompiledChangeRequestMutation::Clear { field } => {
                        Ok(CandidateChangeRequestMutation::Clear {
                            field: field.clone(),
                        })
                    }
                    CompiledChangeRequestMutation::Set { field, value } => {
                        let value = match value {
                            CompiledChangeRequestValue::FromField { field } => {
                                CandidateChangeRequestValue::FromRequestField {
                                    field: field.clone(),
                                }
                            }
                            CompiledChangeRequestValue::FromEffect {
                                effect,
                                target_entity_id,
                            } => CandidateChangeRequestValue::FromEffect {
                                effect: effect.clone(),
                                target_entity_id: target_entity_id.clone(),
                            },
                        };
                        Ok(CandidateChangeRequestMutation::Set {
                            field: field.clone(),
                            value,
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CandidateChangeRequestEffect {
                id: effect.id.clone(),
                target: CandidateChangeRequestTarget {
                    entity_id: effect.target.entity_id.clone(),
                    binding,
                },
                operation: effect.operation,
                mutations,
                depends_on: effect.depends_on.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompiledEffectPlanCandidate {
        effects,
        planner_binding: CandidatePlannerBinding {
            kind: "declarative",
            abi_identifier: CHANGE_REQUEST_PLAN_ABI_V1.to_owned(),
            script_sha256: None,
        },
    })
}

pub(crate) fn engine(deadline: Option<Instant>) -> Engine {
    platform::build_engine(&SCRIPT_PROFILE, deadline, |engine| {
        engine.register_fn("join", join_strings);
    })
}

fn join_strings(
    values: &mut Array,
    separator: ImmutableString,
) -> Result<ImmutableString, Box<EvalAltResult>> {
    let strings = values
        .iter()
        .map(|value| value.clone().try_cast::<ImmutableString>())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            EvalAltResult::ErrorRuntime("join requires strings".into(), Position::NONE)
        })?;
    let joined = strings
        .iter()
        .map(ImmutableString::as_str)
        .collect::<Vec<_>>()
        .join(separator.as_str());
    if joined.len() > MAXIMUM_STRING_BYTES {
        return Err(
            EvalAltResult::ErrorDataTooLarge("joined string".to_owned(), Position::NONE).into(),
        );
    }
    Ok(joined.into())
}

fn planner_context(
    planner: &CompiledChangeRequestPlanner,
    input: &JsonMap<String, Value>,
) -> Result<Dynamic, ChangeRequestPlannerError> {
    if planner.request_fields.len() > MAXIMUM_MAP_ENTRIES {
        return Err(ChangeRequestPlannerError::Resource);
    }
    let mut request = Map::new();
    for field in &planner.request_fields {
        if field.len() > MAXIMUM_STRING_BYTES {
            return Err(ChangeRequestPlannerError::Resource);
        }
        if let Some(value) = input.get(field) {
            request.insert(field.clone().into(), json_to_dynamic(value, 0)?);
        }
    }
    let mut ctx = Map::new();
    ctx.insert("request".into(), Dynamic::from(request));
    Ok(Dynamic::from(ctx))
}

pub(crate) fn json_to_dynamic(
    value: &Value,
    depth: usize,
) -> Result<Dynamic, ChangeRequestPlannerError> {
    if depth > MAXIMUM_VALUE_DEPTH {
        return Err(ChangeRequestPlannerError::Resource);
    }
    match value {
        Value::Null => Ok(Dynamic::UNIT),
        Value::Bool(value) => Ok(Dynamic::from_bool(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(Dynamic::from_int)
            .ok_or(ChangeRequestPlannerError::Result),
        Value::String(value) if value.len() <= MAXIMUM_STRING_BYTES => {
            Ok(Dynamic::from(value.clone()))
        }
        Value::Array(values) if values.len() <= MAXIMUM_ARRAY_ITEMS => values
            .iter()
            .map(|value| json_to_dynamic(value, depth + 1))
            .collect::<Result<Array, _>>()
            .map(Dynamic::from),
        Value::Object(values) if values.len() <= MAXIMUM_MAP_ENTRIES => values
            .iter()
            .map(|(key, value)| {
                if key.len() > MAXIMUM_STRING_BYTES {
                    return Err(ChangeRequestPlannerError::Resource);
                }
                Ok((key.clone().into(), json_to_dynamic(value, depth + 1)?))
            })
            .collect::<Result<Map, _>>()
            .map(Dynamic::from),
        _ => Err(ChangeRequestPlannerError::Resource),
    }
}

fn decode_plan(
    plan: &CompiledChangeRequest,
    planner: &CompiledChangeRequestPlanner,
    result: Dynamic,
) -> Result<CompiledEffectPlanCandidate, ChangeRequestPlannerError> {
    let map = result
        .try_cast::<Map>()
        .ok_or(ChangeRequestPlannerError::Result)?;
    exact_keys(&map, &["effects"], &[])?;
    let effects = map
        .get("effects")
        .and_then(Dynamic::read_lock::<Array>)
        .ok_or(ChangeRequestPlannerError::Result)?;
    if effects.is_empty() || effects.len() > usize::from(plan.maximum_targets) {
        return Err(ChangeRequestPlannerError::Ceiling);
    }
    let mut decoded = Vec::with_capacity(effects.len());
    let mut ids = BTreeSet::new();
    for (index, effect) in effects.iter().cloned().enumerate() {
        let effect = decode_effect(planner, effect, index)?;
        if !ids.insert(effect.id.clone()) {
            return Err(ChangeRequestPlannerError::Result);
        }
        decoded.push(effect);
    }
    if decoded
        .iter()
        .map(|effect| effect.mutations.len())
        .sum::<usize>()
        > usize::from(plan.maximum_field_mutations)
    {
        return Err(ChangeRequestPlannerError::Ceiling);
    }
    for effect in &decoded {
        for dependency in &effect.depends_on {
            let source = decoded
                .iter()
                .find(|candidate| &candidate.id == dependency)
                .ok_or(ChangeRequestPlannerError::Result)?;
            let expected_entity = effect
                .mutations
                .iter()
                .find_map(|mutation| match mutation {
                    CandidateChangeRequestMutation::Set {
                        value:
                            CandidateChangeRequestValue::FromEffect {
                                effect: source_id,
                                target_entity_id,
                            },
                        ..
                    } if source_id == dependency => Some(target_entity_id),
                    _ => None,
                })
                .ok_or(ChangeRequestPlannerError::Result)?;
            if source.operation != Operation::Create || &source.target.entity_id != expected_entity
            {
                return Err(ChangeRequestPlannerError::Ceiling);
            }
        }
    }
    let decoded = order_candidates(decoded)?;
    Ok(CompiledEffectPlanCandidate {
        effects: decoded,
        planner_binding: CandidatePlannerBinding {
            kind: "rhai",
            abi_identifier: planner.abi.clone(),
            script_sha256: Some(planner.script_sha256.clone()),
        },
    })
}

pub(crate) fn order_candidates(
    effects: Vec<CandidateChangeRequestEffect>,
) -> Result<Vec<CandidateChangeRequestEffect>, ChangeRequestPlannerError> {
    fn visit(
        id: &str,
        effects: &std::collections::BTreeMap<String, CandidateChangeRequestEffect>,
        visiting: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
        ordered: &mut Vec<String>,
    ) -> Result<(), ChangeRequestPlannerError> {
        if done.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(ChangeRequestPlannerError::Result);
        }
        let effect = effects.get(id).ok_or(ChangeRequestPlannerError::Result)?;
        for dependency in &effect.depends_on {
            visit(dependency, effects, visiting, done, ordered)?;
        }
        visiting.remove(id);
        done.insert(id.to_owned());
        ordered.push(id.to_owned());
        Ok(())
    }

    let by_id = effects
        .into_iter()
        .map(|effect| (effect.id.clone(), effect))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut ordered = Vec::new();
    for id in by_id.keys() {
        visit(id, &by_id, &mut visiting, &mut done, &mut ordered)?;
    }
    Ok(ordered
        .into_iter()
        .filter_map(|id| by_id.get(&id).cloned())
        .collect())
}

fn decode_effect(
    planner: &CompiledChangeRequestPlanner,
    value: Dynamic,
    index: usize,
) -> Result<CandidateChangeRequestEffect, ChangeRequestPlannerError> {
    let map = value
        .try_cast::<Map>()
        .ok_or(ChangeRequestPlannerError::Result)?;
    exact_keys(&map, &["target", "operation"], &["id", "set", "clear"])?;
    let id = map
        .get("id")
        .map(dynamic_string)
        .transpose()?
        .unwrap_or_else(|| format!("effect-{}", index + 1));
    let operation = match map
        .get("operation")
        .map(dynamic_string)
        .transpose()?
        .as_deref()
    {
        Some("patch") => Operation::Patch,
        Some("create") => Operation::Create,
        _ => return Err(ChangeRequestPlannerError::Result),
    };
    let target_map = map
        .get("target")
        .and_then(Dynamic::read_lock::<Map>)
        .ok_or(ChangeRequestPlannerError::Result)?;
    let (target_entity, binding, write) =
        match (target_map.get("fromField"), target_map.get("entity")) {
            (Some(field), None) if operation == Operation::Patch => {
                exact_keys(&target_map, &["fromField"], &[])?;
                let from_field = dynamic_string(field)?;
                let write = planner
                    .writes
                    .iter()
                    .find(|write| {
                        write.operation == operation
                            && write.target_from_field.as_deref() == Some(&from_field)
                    })
                    .ok_or(ChangeRequestPlannerError::Ceiling)?;
                (
                    write.target_entity_id.clone(),
                    CandidateChangeRequestTargetBinding::Existing { from_field },
                    write,
                )
            }
            (None, Some(entity)) if operation == Operation::Create => {
                exact_keys(&target_map, &["entity"], &[])?;
                let entity = dynamic_string(entity)?;
                let write = planner
                    .writes
                    .iter()
                    .find(|write| {
                        write.operation == operation
                            && write.target_entity_id == entity
                            && write.target_from_field.is_none()
                    })
                    .ok_or(ChangeRequestPlannerError::Ceiling)?;
                (
                    entity,
                    CandidateChangeRequestTargetBinding::ReservedCreate { effect: id.clone() },
                    write,
                )
            }
            _ => return Err(ChangeRequestPlannerError::Result),
        };
    if operation == Operation::Create && !map.contains_key("id") {
        return Err(ChangeRequestPlannerError::Result);
    }
    let mutations = decode_write_mutations(write, &map)?;
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
    Ok(CandidateChangeRequestEffect {
        id,
        target: CandidateChangeRequestTarget {
            entity_id: target_entity,
            binding,
        },
        operation,
        mutations,
        depends_on,
    })
}

pub(crate) fn decode_write_mutations(
    write: &CompiledChangeRequestPlannerWrite,
    map: &Map,
) -> Result<Vec<CandidateChangeRequestMutation>, ChangeRequestPlannerError> {
    // The mutation rules are product semantics shared with the action
    // validator; this adapter only carries the planner's Rhai map into the
    // backend-neutral member list the shared decoder works on.
    let members: Vec<(String, crate::action_outcome::ProposedValue)> = map
        .iter()
        .map(|(key, value)| {
            (
                key.to_string(),
                crate::action_outcome::rhai_document(value.clone()),
            )
        })
        .collect();
    crate::action_outcome::decode_slot_mutations(write, &members)
        .map_err(|diagnostic| diagnostic.kind)
}

pub(crate) fn dynamic_string(value: &Dynamic) -> Result<String, ChangeRequestPlannerError> {
    value
        .clone()
        .try_cast::<ImmutableString>()
        .filter(|value| value.len() <= MAXIMUM_STRING_BYTES)
        .map(|value| value.to_string())
        .ok_or(ChangeRequestPlannerError::Result)
}

pub(crate) fn exact_keys(
    map: &Map,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ChangeRequestPlannerError> {
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(ChangeRequestPlannerError::Result);
    }
    Ok(())
}
