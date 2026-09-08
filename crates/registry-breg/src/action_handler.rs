// SPDX-License-Identifier: Apache-2.0
//! Input-only immediate action evaluation inside the shared bounded Rhai kernel.

use crate::{
    contract::{Operation, ACTION_HANDLER_ABI_V1},
    data::{validate_field_value, FieldValue},
    model::*,
    rhai_planner::{
        self, CandidateChangeRequestMutation, CandidateChangeRequestValue,
        ChangeRequestPlannerError,
    },
};
#[cfg(feature = "postgres-test")]
use std::collections::BTreeMap;

use rhai::{Array, CallFnOptions, Dynamic, Map, Scope, AST};
use serde_json::{Map as JsonMap, Value};
use std::{collections::BTreeSet, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionHandlerError {
    Input,
    Source,
    Entrypoint,
    Execution,
    Result,
    Ceiling,
    Resource,
    Deadline,
    Evidence,
}
impl ActionHandlerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Evidence => "action.evidence.failed",
            Self::Input => "action.input.invalid",
            Self::Source => "action.handler.source",
            Self::Entrypoint => "action.handler.entrypoint",
            Self::Execution => "action.handler.execution",
            Self::Result => "action.handler.result",
            Self::Ceiling => "action.handler.ceiling",
            Self::Resource => "action.handler.resource",
            Self::Deadline => "action.handler.deadline",
        }
    }
    pub const fn problem_detail(self) -> &'static str {
        match self {
            Self::Evidence => "The declared Evidence dependency could not be accepted.",
            Self::Input => "The action inputs do not match the declared input contract.",
            Self::Source => "The action handler failed: action.handler.source.",
            Self::Entrypoint => "The action handler failed: action.handler.entrypoint.",
            Self::Execution => "The action handler failed: action.handler.execution.",
            Self::Result => "The action handler failed: action.handler.result.",
            Self::Ceiling => "The action handler failed: action.handler.ceiling.",
            Self::Resource => "The action handler failed: action.handler.resource.",
            Self::Deadline => "The Registry mutation service is unavailable.",
        }
    }
}
impl std::fmt::Display for ActionHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ActionHandlerError {}
impl From<ChangeRequestPlannerError> for ActionHandlerError {
    fn from(error: ChangeRequestPlannerError) -> Self {
        match error {
            ChangeRequestPlannerError::Source => Self::Source,
            ChangeRequestPlannerError::Entrypoint => Self::Entrypoint,
            ChangeRequestPlannerError::Execution => Self::Execution,
            ChangeRequestPlannerError::Ceiling => Self::Ceiling,
            ChangeRequestPlannerError::Resource => Self::Resource,
            ChangeRequestPlannerError::Deadline => Self::Deadline,
            _ => Self::Result,
        }
    }
}

/// Local authoring diagnostics contain only compiled locations and static repair
/// messages. Runtime callers retain the closed error vocabulary and, for a
/// failed dependency, only its matched compiled capability location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionHandlerDiagnostic {
    pub kind: ActionHandlerError,
    /// A matched compiled capability only, never an unknown script argument.
    pub evidence_capability: Option<String>,
    pub slot: Option<String>,
    pub field: Option<String>,
    pub message: &'static str,
}

impl ActionHandlerDiagnostic {
    fn new(kind: ActionHandlerError, message: &'static str) -> Self {
        Self {
            kind,
            evidence_capability: None,
            slot: None,
            field: None,
            message,
        }
    }

    fn at_slot(mut self, slot: &CompiledActionHandlerWrite) -> Self {
        self.slot = Some(slot.id.clone());
        self
    }
}

impl From<ActionHandlerError> for ActionHandlerDiagnostic {
    fn from(kind: ActionHandlerError) -> Self {
        Self {
            kind,
            evidence_capability: None,
            slot: None,
            field: None,
            message: kind.problem_detail(),
        }
    }
}

impl From<ChangeRequestPlannerError> for ActionHandlerDiagnostic {
    fn from(kind: ChangeRequestPlannerError) -> Self {
        ActionHandlerError::from(kind).into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionHandlerOutcome {
    Effects(Vec<CompiledActionEffect>),
    Refusal(ActionHandlerRefusal),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionHandlerRefusal {
    pub code: String,
    pub label: String,
    pub field: Option<String>,
}

pub fn compile_source(source: &str) -> Result<AST, ActionHandlerError> {
    let ast =
        rhai_planner::compile_entrypoint(source, "handle").map_err(ActionHandlerError::from)?;
    // An invalid helper arity would otherwise be a catchable language dispatch
    // error before the host can poison the evaluation. Reject it at compilation.
    let mut valid = true;
    ast.walk(&mut |nodes| {
        let call = match nodes.last() {
            Some(rhai::ASTNode::Expr(rhai::Expr::FnCall(call, _)))
            | Some(rhai::ASTNode::Stmt(rhai::Stmt::FnCall(call, _))) => Some(call),
            _ => None,
        };
        if call.is_some_and(|call| {
            call.namespace
                .path
                .first()
                .is_some_and(|part| part.as_str() == "evidence")
                && (call.namespace.path.len() != 1
                    || call.name != "resolve"
                    || call.args.len() != 2)
        }) {
            valid = false;
            return false;
        }
        true
    });
    if !valid {
        return Err(ActionHandlerError::Source);
    }
    Ok(ast)
}

#[cfg(feature = "postgres-test")]
static TEST_INVOCATIONS: std::sync::Mutex<BTreeMap<String, (usize, bool, bool)>> =
    std::sync::Mutex::new(BTreeMap::new());
#[cfg(feature = "postgres-test")]
pub fn reset_test_action_handler_invocation_count(action_id: &str) {
    TEST_INVOCATIONS
        .lock()
        .unwrap()
        .insert(action_id.to_owned(), (0, false, false));
}
#[cfg(feature = "postgres-test")]
pub fn test_action_handler_invocation_count(action_id: &str) -> usize {
    TEST_INVOCATIONS
        .lock()
        .unwrap()
        .get(action_id)
        .map_or(0, |entry| entry.0)
}
#[cfg(feature = "postgres-test")]
pub fn fail_next_test_action_handler_invocation(action_id: &str) {
    TEST_INVOCATIONS
        .lock()
        .unwrap()
        .entry(action_id.to_owned())
        .or_default()
        .1 = true;
}

/// Model a scheduling pause inside Rhai's execution callback until the original
/// absolute deadline. This test hook never changes source, bindings, or budgets.
#[cfg(feature = "postgres-test")]
pub fn expire_next_test_action_handler_during_evaluation(action_id: &str) {
    TEST_INVOCATIONS
        .lock()
        .unwrap()
        .entry(action_id.to_owned())
        .or_default()
        .2 = true;
}

pub fn evaluate_action(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<ActionHandlerOutcome, ActionHandlerError> {
    evaluate_action_detailed(action, inputs, deadline).map_err(|diagnostic| diagnostic.kind)
}

/// Evaluate through the same runtime verifier with actionable local diagnostics.
pub fn evaluate_action_detailed(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    validate_inputs(action, inputs)?;
    evaluate_admitted_action_detailed(action, inputs, deadline)
}

fn validate_inputs(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
) -> Result<(), ActionHandlerDiagnostic> {
    if inputs
        .keys()
        .any(|id| !action.inputs.iter().any(|input| &input.id == id))
    {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Input,
            "Use only declared input IDs in the input object; do not wrap it in an HTTP request body.",
        ));
    }
    for input in &action.inputs {
        match inputs.get(&input.id) {
            None | Some(Value::Null) if input.required => {
                return Err(ActionHandlerDiagnostic {
                    kind: ActionHandlerError::Input,
                    evidence_capability: None,
                    slot: None,
                    field: Some(input.id.clone()),
                    message: "Supply a non-null value for this required input.",
                })
            }
            Some(value)
                if !value.is_null()
                    && !validate_field_value(FieldValue::Json(value), &input.field_type) =>
            {
                return Err(ActionHandlerDiagnostic {
                    kind: ActionHandlerError::Input,
                    evidence_capability: None,
                    slot: None,
                    field: Some(input.id.clone()),
                    message: "Use an input value matching the declared type and bounds.",
                })
            }
            _ => {}
        }
    }
    Ok(())
}

/// Runtime admission already validates and projects action inputs. Keep the
/// evaluator's resource bounds while avoiding a second input-validation pass.
pub(crate) fn evaluate_admitted_action_detailed(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    evaluate_with_engine(action, inputs, deadline, None, None)
}

type EvidenceResolver =
    std::sync::Arc<dyn Fn(&str, Value) -> Result<Value, ActionHandlerError> + Send + Sync>;

/// Execute the same bounded handler and result verifier with declared Evidence
/// capabilities. Local fixtures supply synthetic assertions through this seam.
pub fn evaluate_action_with_evidence(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: impl Fn(&str, Value) -> Result<Value, ActionHandlerError> + Send + Sync + 'static,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    validate_inputs(action, inputs)?;
    evaluate_with_engine(
        action,
        inputs,
        deadline,
        Some(std::sync::Arc::new(resolver)),
        None,
    )
}

pub(crate) fn evaluate_with_engine(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: Option<EvidenceResolver>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    if serde_json::to_vec(inputs)
        .map_err(|_| ActionHandlerError::Result)?
        .len()
        > action.maximum_snapshot_bytes as usize
    {
        return Err(ActionHandlerError::Resource.into());
    }
    let Some(handler) = &action.handler else {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Source,
            "Evaluate a declared handler; fixed actions use their compiled effects directly.",
        ));
    };
    if handler.abi != ACTION_HANDLER_ABI_V1
        && !(handler.abi == "registry.action-handler/v2" && resolver.is_some())
    {
        return Err(ActionHandlerError::Source.into());
    }
    let source =
        std::str::from_utf8(&handler.script_bytes).map_err(|_| ActionHandlerError::Source)?;
    let ast = compile_source(source)?;
    let mut ctx = Map::new();
    ctx.insert(
        "inputs".into(),
        rhai_planner::json_to_dynamic(&Value::Object(inputs.clone()), 0)?,
    );
    #[cfg(feature = "postgres-test")]
    let expire_during_execution = {
        let mut invocations = TEST_INVOCATIONS.lock().unwrap();
        let entry = invocations.entry(action.id.clone()).or_default();
        entry.0 += 1;
        if std::mem::take(&mut entry.1) {
            return Err(ActionHandlerError::Execution.into());
        }
        std::mem::take(&mut entry.2)
    };
    let mut engine = rhai_planner::engine(Some(deadline));
    let poisoned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failed_capability = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let dependency_diagnostic = || {
        let mut diagnostic = ActionHandlerDiagnostic::from(ActionHandlerError::Evidence);
        diagnostic.evidence_capability = failed_capability.lock().ok().and_then(|id| id.clone());
        diagnostic
    };
    if let Some(resolver) = resolver {
        let failure = poisoned.clone();
        let failed_location = failed_capability.clone();
        let cancelled = cancellation.clone();
        let capabilities = action.evidence.clone();
        let calls = std::sync::Mutex::new(BTreeSet::<String>::new());
        let mut module = rhai::Module::new();
        module.set_native_fn("resolve", move |alias: Dynamic, subjects: Dynamic| {
            let refused = || {
                Box::new(rhai::EvalAltResult::ErrorRuntime(
                    "Evidence dependency failed".into(),
                    rhai::Position::NONE,
                ))
            };
            let mut known_alias = None;
            let result = (|| {
                if failure.load(std::sync::atomic::Ordering::Acquire)
                    || Instant::now() >= deadline
                    || cancelled
                        .as_ref()
                        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
                {
                    return Err(ActionHandlerError::Evidence);
                }
                let alias = alias
                    .clone()
                    .try_cast::<rhai::ImmutableString>()
                    .ok_or(ActionHandlerError::Evidence)?;
                let capability = capabilities
                    .iter()
                    .find(|capability| capability.id == alias.as_str())
                    .ok_or(ActionHandlerError::Evidence)?;
                known_alias = Some(capability.id.clone());
                let subjects = subjects
                    .clone()
                    .try_cast::<Map>()
                    .ok_or(ActionHandlerError::Evidence)?;
                {
                    let mut calls = calls.lock().map_err(|_| ActionHandlerError::Evidence)?;
                    if calls.len() >= 2 || !calls.insert(alias.to_string()) {
                        return Err(ActionHandlerError::Evidence);
                    }
                }
                let subjects = rhai::serde::from_dynamic::<Value>(&Dynamic::from(subjects))
                    .map_err(|_| ActionHandlerError::Evidence)?;

                let typed_subjects = serde_json::from_value(subjects.clone())
                    .map_err(|_| ActionHandlerError::Evidence)?;
                crate::action_evidence_validation::validate_call_arguments(
                    capability,
                    &typed_subjects,
                )
                .map_err(|_| ActionHandlerError::Evidence)?;
                let output = resolver(alias.as_str(), subjects)?;
                let typed_outputs = serde_json::from_value(output.clone())
                    .map_err(|_| ActionHandlerError::Evidence)?;
                crate::action_evidence_validation::validate_selected_outputs(
                    capability,
                    &typed_outputs,
                )
                .map_err(|_| ActionHandlerError::Evidence)?;
                rhai_planner::json_to_dynamic(&output, 0).map_err(ActionHandlerError::from)
            })();
            match result {
                Ok(value) => Ok(value),
                Err(_) => {
                    if !failure.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        if let Ok(mut location) = failed_location.lock() {
                            *location = known_alias;
                        }
                    }
                    Err(refused())
                }
            }
        });
        engine.register_static_module("evidence", module.into());
    }
    if let Some(cancelled) = cancellation.clone() {
        engine.on_progress(move |_| {
            (Instant::now() >= deadline || cancelled.load(std::sync::atomic::Ordering::Acquire))
                .then_some(Dynamic::UNIT)
        });
    }
    #[cfg(feature = "postgres-test")]
    if expire_during_execution {
        engine.on_progress(move |_| {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            (Instant::now() >= deadline).then_some(Dynamic::UNIT)
        });
    }
    let result = engine
        .call_fn_with_options::<Dynamic>(
            CallFnOptions::new().eval_ast(false),
            &mut Scope::new(),
            &ast,
            "handle",
            (Dynamic::from(ctx),),
        )
        .map_err(|error| {
            let kind = if Instant::now() >= deadline
                || cancellation
                    .as_ref()
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
            {
                ActionHandlerError::Deadline
            } else if poisoned.load(std::sync::atomic::Ordering::Acquire) {
                ActionHandlerError::Evidence
            } else if matches!(
                *error,
                rhai::EvalAltResult::ErrorTooManyOperations(..)
                    | rhai::EvalAltResult::ErrorStackOverflow(..)
                    | rhai::EvalAltResult::ErrorDataTooLarge(..)
            ) {
                ActionHandlerError::Resource
            } else {
                ActionHandlerError::Execution
            };
            if kind == ActionHandlerError::Evidence {
                dependency_diagnostic()
            } else {
                kind.into()
            }
        })?;
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    if poisoned.load(std::sync::atomic::Ordering::Acquire) {
        return Err(dependency_diagnostic());
    }
    if cancellation
        .as_ref()
        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
    {
        return Err(ActionHandlerError::Deadline.into());
    }
    let mut remaining = action.maximum_snapshot_bytes as usize;
    bound_result(&result, 0, &mut remaining)?;
    let outcome = decode_result(action, handler, result)?;
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    Ok(outcome)
}

fn bound_result(
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
    if let Some(value) = value.read_lock::<rhai::ImmutableString>() {
        *remaining = remaining
            .checked_sub(value.len())
            .ok_or(ActionHandlerError::Resource)?;
    } else if let Some(values) = value.read_lock::<Array>() {
        if values.len() > rhai_planner::MAXIMUM_ARRAY_ITEMS {
            return Err(ActionHandlerError::Resource);
        }
        for value in values.iter() {
            bound_result(value, depth + 1, remaining)?;
        }
    } else if let Some(values) = value.read_lock::<Map>() {
        if values.len() > rhai_planner::MAXIMUM_MAP_ENTRIES {
            return Err(ActionHandlerError::Resource);
        }
        for (key, value) in values.iter() {
            *remaining = remaining
                .checked_sub(key.len())
                .ok_or(ActionHandlerError::Resource)?;
            bound_result(value, depth + 1, remaining)?;
        }
    }
    Ok(())
}

fn decode_result(
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    result: Dynamic,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let map = result.try_cast::<Map>().ok_or_else(|| {
        ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "Return a map containing either effects or refusal.",
        )
    })?;
    if map.contains_key("effects") && map.contains_key("refusal") {
        return Err(ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "Return either effects or refusal, never both.",
        ));
    }
    if let Some(refusal) = map.get("refusal") {
        rhai_planner::exact_keys(&map, &["refusal"], &[]).map_err(|_| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "A refusal outcome may contain only refusal.",
            )
        })?;
        let refusal = refusal.read_lock::<Map>().ok_or_else(|| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Return refusal as a map with code and an optional field.",
            )
        })?;
        rhai_planner::exact_keys(&refusal, &["code"], &["field"]).map_err(|_| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "A refusal requires code and may contain only an optional field; declare its label in the handler catalogue.",
            )
        })?;
        let code = rhai_planner::dynamic_string(&refusal["code"]).map_err(|_| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Use a string code from the handler's declared refusal catalogue.",
            )
        })?;
        let label = handler.refusals.get(&code).cloned().ok_or_else(|| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Use a code from the handler's declared refusal catalogue.",
            )
        })?;
        let field = refusal
            .get("field")
            .map(rhai_planner::dynamic_string)
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
        return Ok(ActionHandlerOutcome::Refusal(ActionHandlerRefusal {
            code,
            label,
            field,
        }));
    }
    rhai_planner::exact_keys(&map, &["effects"], &[]).map_err(|_| {
        ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "An effects outcome must contain only effects.",
        )
    })?;
    let results = map["effects"].read_lock::<Array>().ok_or_else(|| {
        ActionHandlerDiagnostic::new(
            ActionHandlerError::Result,
            "Return effects as a non-empty list of declared write slots.",
        )
    })?;
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
    for result in results.iter() {
        let effect = result.clone().try_cast::<Map>().ok_or_else(|| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Return each effect as a map with id and set or clear.",
            )
        })?;
        let id = effect
            .get("id")
            .ok_or_else(|| {
                ActionHandlerDiagnostic::new(
                    ActionHandlerError::Result,
                    "Give each effect an id from the handler's declared write slots.",
                )
            })
            .and_then(|id| {
                rhai_planner::dynamic_string(id).map_err(|_| {
                    ActionHandlerDiagnostic::new(
                        ActionHandlerError::Result,
                        "Use a string id from the handler's declared write slots.",
                    )
                })
            })?;
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
        rhai_planner::exact_keys(&effect, &["id"], &["set", "clear"]).map_err(|_| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "An effect may contain only id, set and clear; the declared slot fixes its target and operation.",
            )
            .at_slot(slot)
        })?;
        if !selected.insert(id.clone()) {
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Result,
                "Emit each declared write slot at most once.",
            )
            .at_slot(slot));
        }
        let mutations = rhai_planner::decode_write_mutations_detailed(&slot.ceiling, &effect)
            .map_err(|diagnostic| ActionHandlerDiagnostic {
                kind: diagnostic.kind.into(),
                evidence_capability: None,
                slot: Some(slot.id.clone()),
                field: diagnostic.field,
                message: diagnostic.message,
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
            Some(from_field) => rhai_planner::CandidateChangeRequestTargetBinding::Existing {
                from_field: from_field.clone(),
            },
            None => rhai_planner::CandidateChangeRequestTargetBinding::ReservedCreate {
                effect: id.clone(),
            },
        };
        effects.push(rhai_planner::CandidateChangeRequestEffect {
            id,
            target: rhai_planner::CandidateChangeRequestTarget {
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
