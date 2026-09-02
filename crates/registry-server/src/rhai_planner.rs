// SPDX-License-Identifier: Apache-2.0

//! Closed, bounded Rhai kernel for change-request effect planning.

use std::{collections::BTreeSet, time::Instant};

#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicUsize, Ordering};

use rhai::{
    module_resolvers::DummyModuleResolver, Array, CallFnOptions, Dynamic, Engine, EvalAltResult,
    ImmutableString, Map, Position, Scope, AST,
};
use serde_json::{Map as JsonMap, Number, Value};

use crate::{
    contract::{FieldTypeSource, Operation, CHANGE_REQUEST_PLAN_ABI_V1},
    data::{validate_field_value, FieldValue},
    model::{
        CompiledChangeRequest, CompiledChangeRequestApplicationMode,
        CompiledChangeRequestDisposition, CompiledChangeRequestMutation,
        CompiledChangeRequestPlanner, CompiledChangeRequestPlannerWrite,
        CompiledChangeRequestTargetBinding, CompiledChangeRequestValue,
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
    Disposition,
    Resource,
    Deadline,
}

impl ChangeRequestPlannerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Source => "change_request.planner.source",
            Self::Entrypoint => "change_request.planner.entrypoint",
            Self::Execution => "change_request.planner.execution",
            Self::Result => "change_request.planner.result",
            Self::Ceiling => "change_request.planner.ceiling",
            Self::Disposition => "change_request.planner.disposition",
            Self::Resource => "change_request.planner.resource",
            Self::Deadline => "change_request.planner.deadline",
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
    pub disposition: CompiledChangeRequestDisposition,
    pub queue_reason: Option<CandidateQueueReason>,
    pub planner_binding: CandidatePlannerBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePlannerBinding {
    pub kind: &'static str,
    pub abi_identifier: String,
    pub script_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateQueueReason {
    pub code: String,
    pub label: String,
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
        if source.len() > MAXIMUM_SOURCE_BYTES {
            return Err(ChangeRequestPlannerError::Source);
        }
        let engine = engine(None);
        let ast = engine
            .compile(source)
            .map_err(|_| ChangeRequestPlannerError::Source)?;
        let mut names = BTreeSet::new();
        let mut entrypoints = 0usize;
        for function in ast.iter_functions() {
            if !names.insert(function.name) {
                return Err(ChangeRequestPlannerError::Entrypoint);
            }
            if function.name == "plan" {
                if function.params.len() != 1 || function.access != rhai::FnAccess::Public {
                    return Err(ChangeRequestPlannerError::Entrypoint);
                }
                entrypoints += 1;
            }
        }
        if entrypoints != 1 {
            return Err(ChangeRequestPlannerError::Entrypoint);
        }
        Ok(ast)
    }
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
    let result = engine
        .call_fn_with_options::<Dynamic>(
            CallFnOptions::new().eval_ast(false),
            &mut Scope::new(),
            &ast,
            "plan",
            (ctx,),
        )
        .map_err(|error| {
            if Instant::now() >= deadline {
                ChangeRequestPlannerError::Deadline
            } else if matches!(
                *error,
                rhai::EvalAltResult::ErrorTooManyOperations(..)
                    | rhai::EvalAltResult::ErrorStackOverflow(..)
                    | rhai::EvalAltResult::ErrorDataTooLarge(..)
            ) {
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
    let disposition = match plan.application.mode {
        CompiledChangeRequestApplicationMode::Manual => CompiledChangeRequestDisposition::Queue,
        CompiledChangeRequestApplicationMode::Automatic => CompiledChangeRequestDisposition::Apply,
        CompiledChangeRequestApplicationMode::Planner => {
            return Err(ChangeRequestPlannerError::Disposition)
        }
    };
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
        disposition,
        queue_reason: None,
        planner_binding: CandidatePlannerBinding {
            kind: "declarative",
            abi_identifier: CHANGE_REQUEST_PLAN_ABI_V1.to_owned(),
            script_sha256: None,
        },
    })
}

fn engine(deadline: Option<Instant>) -> Engine {
    let mut engine = Engine::new();
    engine.set_module_resolver(DummyModuleResolver::new());
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});
    engine
        .set_max_operations(MAXIMUM_OPERATIONS)
        .set_max_call_levels(MAXIMUM_CALL_DEPTH)
        .set_max_expr_depths(MAXIMUM_EXPRESSION_DEPTH, MAXIMUM_EXPRESSION_DEPTH)
        .set_max_modules(0)
        .set_max_string_size(MAXIMUM_STRING_BYTES)
        .set_max_array_size(MAXIMUM_ARRAY_ITEMS)
        .set_max_map_size(MAXIMUM_MAP_ENTRIES)
        .set_allow_anonymous_fn(false)
        .disable_symbol("import")
        .disable_symbol("export")
        .disable_symbol("eval")
        .disable_symbol("print")
        .disable_symbol("debug");
    engine.register_fn("join", join_strings);
    if let Some(deadline) = deadline {
        engine.on_progress(move |_| (Instant::now() >= deadline).then_some(Dynamic::UNIT));
    }
    engine
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

fn json_to_dynamic(value: &Value, depth: usize) -> Result<Dynamic, ChangeRequestPlannerError> {
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
    exact_keys(&map, &["effects"], &["disposition", "reasonCode"])?;
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
    let authored_disposition = map.get("disposition").map(dynamic_string).transpose()?;
    let reason_code = map.get("reasonCode").map(dynamic_string).transpose()?;
    let disposition = match plan.application.mode {
        CompiledChangeRequestApplicationMode::Manual => {
            if authored_disposition.is_some() || reason_code.is_some() {
                return Err(ChangeRequestPlannerError::Disposition);
            }
            CompiledChangeRequestDisposition::Queue
        }
        CompiledChangeRequestApplicationMode::Automatic => {
            if authored_disposition.is_some() || reason_code.is_some() {
                return Err(ChangeRequestPlannerError::Disposition);
            }
            CompiledChangeRequestDisposition::Apply
        }
        CompiledChangeRequestApplicationMode::Planner => match authored_disposition.as_deref() {
            Some("apply") if reason_code.is_none() => CompiledChangeRequestDisposition::Apply,
            Some("queue") if reason_code.is_some() => CompiledChangeRequestDisposition::Queue,
            _ => return Err(ChangeRequestPlannerError::Disposition),
        },
    };
    if plan.application.mode == CompiledChangeRequestApplicationMode::Planner
        && !plan.application.allowed_dispositions.contains(&disposition)
    {
        return Err(ChangeRequestPlannerError::Disposition);
    }
    let queue_reason = match (disposition, reason_code) {
        (CompiledChangeRequestDisposition::Queue, Some(code)) => {
            let label = plan
                .application
                .queue_reasons
                .get(&code)
                .cloned()
                .ok_or(ChangeRequestPlannerError::Disposition)?;
            Some(CandidateQueueReason { code, label })
        }
        (CompiledChangeRequestDisposition::Queue, None)
            if plan.application.mode == CompiledChangeRequestApplicationMode::Manual =>
        {
            None
        }
        (CompiledChangeRequestDisposition::Apply, None) => None,
        _ => return Err(ChangeRequestPlannerError::Disposition),
    };
    Ok(CompiledEffectPlanCandidate {
        effects: decoded,
        disposition,
        queue_reason,
        planner_binding: CandidatePlannerBinding {
            kind: "rhai",
            abi_identifier: planner.abi.clone(),
            script_sha256: Some(planner.script_sha256.clone()),
        },
    })
}

fn order_candidates(
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
    let mut mutations = Vec::new();
    let mut touched = BTreeSet::new();
    if let Some(set) = map.get("set") {
        let set = set
            .read_lock::<Map>()
            .ok_or(ChangeRequestPlannerError::Result)?;
        for (field, value) in set.iter() {
            if !write.fields.contains(field.as_str()) || !touched.insert(field.to_string()) {
                return Err(ChangeRequestPlannerError::Ceiling);
            }
            mutations.push(CandidateChangeRequestMutation::Set {
                field: field.to_string(),
                value: decode_set_value(write, field, value.clone())?,
            });
        }
    }
    if let Some(clear) = map.get("clear") {
        let clear = clear
            .read_lock::<Array>()
            .ok_or(ChangeRequestPlannerError::Result)?;
        for field in clear.iter() {
            let field = dynamic_string(field)?;
            if operation == Operation::Create
                || write.required_fields.contains(&field)
                || !write.fields.contains(&field)
                || !touched.insert(field.clone())
            {
                return Err(ChangeRequestPlannerError::Ceiling);
            }
            mutations.push(CandidateChangeRequestMutation::Clear { field });
        }
    }
    if mutations.is_empty() {
        return Err(ChangeRequestPlannerError::Result);
    }
    if operation == Operation::Create && !write.required_fields.is_subset(&touched) {
        return Err(ChangeRequestPlannerError::Ceiling);
    }
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

fn decode_set_value(
    write: &CompiledChangeRequestPlannerWrite,
    field: &str,
    value: Dynamic,
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
        let map = value
            .try_cast::<Map>()
            .ok_or(ChangeRequestPlannerError::Result)?;
        match (map.get("fromField"), map.get("fromEffect")) {
            (Some(field), None) => {
                exact_keys(&map, &["fromField"], &[])?;
                let field = dynamic_string(field)?;
                if !sources.request_fields.contains(&field) {
                    return Err(ChangeRequestPlannerError::Ceiling);
                }
                Ok(CandidateChangeRequestValue::FromRequestField { field })
            }
            (None, Some(effect)) => {
                exact_keys(&map, &["fromEffect"], &[])?;
                let effect = dynamic_string(effect)?;
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
        let value = dynamic_to_json(value, 0)?;
        if value.is_null() || !validate_field_value(FieldValue::Json(&value), field_type) {
            return Err(ChangeRequestPlannerError::Result);
        }
        Ok(CandidateChangeRequestValue::Literal(value))
    }
}

fn dynamic_to_json(value: Dynamic, depth: usize) -> Result<Value, ChangeRequestPlannerError> {
    if depth > MAXIMUM_VALUE_DEPTH {
        return Err(ChangeRequestPlannerError::Resource);
    }
    if value.is_unit() {
        return Ok(Value::Null);
    }
    if value.is::<bool>() {
        return Ok(Value::Bool(value.cast()));
    }
    if value.is::<rhai::INT>() {
        return Ok(Value::Number(Number::from(value.cast::<rhai::INT>())));
    }
    if value.is::<ImmutableString>() {
        let value = value.cast::<ImmutableString>();
        if value.len() > MAXIMUM_STRING_BYTES {
            return Err(ChangeRequestPlannerError::Resource);
        }
        return Ok(Value::String(value.to_string()));
    }
    if value.is::<Array>() {
        let array = value.cast::<Array>();
        if array.len() > MAXIMUM_ARRAY_ITEMS {
            return Err(ChangeRequestPlannerError::Resource);
        }
        return array
            .into_iter()
            .map(|value| dynamic_to_json(value, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if value.is::<Map>() {
        let map = value.cast::<Map>();
        if map.len() > MAXIMUM_MAP_ENTRIES {
            return Err(ChangeRequestPlannerError::Resource);
        }
        return map
            .into_iter()
            .map(|(key, value)| {
                if key.len() > MAXIMUM_STRING_BYTES {
                    return Err(ChangeRequestPlannerError::Resource);
                }
                Ok((key.to_string(), dynamic_to_json(value, depth + 1)?))
            })
            .collect::<Result<JsonMap<_, _>, _>>()
            .map(Value::Object);
    }
    Err(ChangeRequestPlannerError::Result)
}

fn dynamic_string(value: &Dynamic) -> Result<String, ChangeRequestPlannerError> {
    value
        .clone()
        .try_cast::<ImmutableString>()
        .filter(|value| value.len() <= MAXIMUM_STRING_BYTES)
        .map(|value| value.to_string())
        .ok_or(ChangeRequestPlannerError::Result)
}

fn exact_keys(
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
