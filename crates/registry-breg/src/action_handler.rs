// SPDX-License-Identifier: Apache-2.0
//! Input-only immediate action evaluation inside the shared bounded Rhai kernel.

use crate::{
    contract::{FieldTypeSource, ACTION_HANDLER_ABI_V1, ACTION_HANDLER_ABI_V2},
    data::{validate_field_value, FieldValue},
    model::*,
    rhai_planner::{self, ChangeRequestPlannerError},
};
#[cfg(feature = "postgres-test")]
use std::collections::BTreeMap;

use registry_platform_script::rhai as platform;
use rhai::{Dynamic, Map, AST};
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
    pub(crate) fn new(kind: ActionHandlerError, message: &'static str) -> Self {
        Self {
            kind,
            evidence_capability: None,
            slot: None,
            field: None,
            message,
        }
    }

    pub(crate) fn at_slot(mut self, slot: &CompiledActionHandlerWrite) -> Self {
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
    compile_source_for_abi(source, ACTION_HANDLER_ABI_V2)
}

pub(crate) fn compile_source_for_abi(source: &str, abi: &str) -> Result<AST, ActionHandlerError> {
    let ast =
        rhai_planner::compile_entrypoint(source, "handle").map_err(ActionHandlerError::from)?;
    // An invalid helper arity would otherwise be a catchable language dispatch
    // error before the host can poison the evaluation. Reject it at compilation,
    // along with every Evidence call in an ABI that does not expose the module.
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
                && (abi != ACTION_HANDLER_ABI_V2
                    || call.namespace.path.len() != 1
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

/// The shared handler input rule for HTTP, direct invocation and local tests.
/// Callers admit optional null separately. The byte check also covers scalar
/// parsers, such as RFC3339, that accept arbitrarily long fractional seconds.
pub(crate) fn validate_input_value(
    value: &Value,
    field_type: &FieldTypeSource,
) -> Result<(), &'static str> {
    if value
        .as_str()
        .is_some_and(|value| value.len() > rhai_planner::MAXIMUM_STRING_BYTES)
    {
        return Err("Use a handler input string of at most 16,384 UTF-8 bytes.");
    }
    if !validate_field_value(FieldValue::Json(value), field_type) {
        return Err("Use an input value matching the declared type and bounds.");
    }
    Ok(())
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
            Some(value) if !value.is_null() => {
                if let Err(message) = validate_input_value(value, &input.field_type) {
                    return Err(ActionHandlerDiagnostic {
                        kind: ActionHandlerError::Input,
                        evidence_capability: None,
                        slot: None,
                        field: Some(input.id.clone()),
                        message,
                    });
                }
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

#[cfg(test)]
#[path = "tests/action_handler_benchmark_tests.rs"]
mod action_handler_benchmark_tests;

pub(crate) fn evaluate_with_engine(
    action: &CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: Option<EvidenceResolver>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let handler = admit_handler(action, inputs, deadline, resolver.as_ref())?;
    // A WASM handler never reaches the Rhai compile path; its module runs
    // through the platform executor in builds that carry the `wasm`
    // feature (a build without it refuses the handler at admission above).
    #[cfg(feature = "wasm")]
    if handler.kind == crate::model::CompiledActionHandlerKind::Wasm {
        return crate::wasm_runtime::evaluate_wasm_handler(action, handler, inputs, deadline);
    }
    let source =
        std::str::from_utf8(&handler.script_bytes).map_err(|_| ActionHandlerError::Source)?;
    let ast = compile_source_for_abi(source, &handler.abi)?;
    execute_compiled_handler(
        action,
        handler,
        &ast,
        inputs,
        deadline,
        resolver,
        cancellation,
    )
}

/// Admission shared by every evaluation entry: the call deadline, the input
/// snapshot ceiling, and the handler ABI/resolver rule.
fn admit_handler<'a>(
    action: &'a CompiledAction,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: Option<&EvidenceResolver>,
) -> Result<&'a CompiledActionHandler, ActionHandlerDiagnostic> {
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
    match handler.kind {
        crate::model::CompiledActionHandlerKind::Rhai => {
            if handler.abi != ACTION_HANDLER_ABI_V1
                && !(handler.abi == ACTION_HANDLER_ABI_V2 && resolver.is_some())
            {
                return Err(ActionHandlerError::Source.into());
            }
        }
        // A build with the `wasm` feature executes the input-only
        // v1 ABI for WASM handlers. The Evidence-enabled v2 ABI stays
        // Rhai-only in this release, and a resolver never reaches a WASM
        // handler.
        #[cfg(feature = "wasm")]
        crate::model::CompiledActionHandlerKind::Wasm
            if handler.abi == ACTION_HANDLER_ABI_V1 && resolver.is_none() => {}
        _ => {
            // A handler tagged with a backend this runtime does not execute
            // is never interpreted as another backend's source.
            return Err(ActionHandlerDiagnostic::new(
                ActionHandlerError::Source,
                "Evaluate a compiled Rhai handler; this runtime does not execute the declared handler backend.",
            ));
        }
    }
    Ok(handler)
}

/// Execute an admitted handler program: context construction, the per-call
/// engine with its resolver registration shape, the bounded call, and result
/// decoding. Shared by the fresh-compile path and the cached-program
/// benchmark variant.
fn execute_compiled_handler(
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    ast: &AST,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: Option<EvidenceResolver>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
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
    let result = platform::call_with_fresh_scope(&engine, ast, "handle", (Dynamic::from(ctx),))
        .map_err(|error| {
            let kind = if Instant::now() >= deadline
                || cancellation
                    .as_ref()
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
            {
                ActionHandlerError::Deadline
            } else if poisoned.load(std::sync::atomic::Ordering::Acquire) {
                ActionHandlerError::Evidence
            } else if platform::classify_failure(&error)
                == platform::RhaiFailureCategory::ResourceExhausted
            {
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
    let document = crate::action_outcome::rhai_document(result);
    crate::action_outcome::bound_document(&document, action.maximum_snapshot_bytes)?;
    let proposed = crate::action_outcome::decode_document(document)?;
    let outcome = crate::action_outcome::validate_proposed_outcome(action, handler, proposed)?;
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    Ok(outcome)
}

/// A handler program compiled once for repeated evaluation.
///
/// Benchmark variant, test-only and crate-private on purpose: the supported
/// evaluation path compiles the handler source on every call, and AST reuse
/// is not public API. The type does not exist outside test builds. A program
/// is constructed only from a compiled action's own validated `script_bytes`
/// through `compile_source_for_abi`, and every evaluation re-checks the
/// handler's ABI and source bytes before the AST is used, so a program cannot
/// drift from the action it was compiled for and no unvalidated AST can be
/// supplied from outside. The Rhai profile and limits applied at compilation
/// are crate constants shared by both paths.
#[cfg(test)]
pub(crate) struct CachedActionHandlerProgram {
    abi: String,
    script_bytes: Vec<u8>,
    ast: AST,
}

#[cfg(test)]
impl CachedActionHandlerProgram {
    /// Compile through the same validated path `evaluate_with_engine` uses.
    pub(crate) fn compile(action: &CompiledAction) -> Result<Self, ActionHandlerError> {
        let Some(handler) = &action.handler else {
            return Err(ActionHandlerError::Source);
        };
        if handler.abi != ACTION_HANDLER_ABI_V1 && handler.abi != ACTION_HANDLER_ABI_V2 {
            return Err(ActionHandlerError::Source);
        }
        let source =
            std::str::from_utf8(&handler.script_bytes).map_err(|_| ActionHandlerError::Source)?;
        let ast = compile_source_for_abi(source, &handler.abi)?;
        Ok(Self {
            abi: handler.abi.clone(),
            script_bytes: handler.script_bytes.clone(),
            ast,
        })
    }

    /// The compiled program for `handler`, or a source error when the
    /// handler's ABI or source bytes no longer match the compiled program.
    fn bound_ast(&self, handler: &CompiledActionHandler) -> Result<&AST, ActionHandlerError> {
        if self.abi != handler.abi || self.script_bytes != handler.script_bytes {
            return Err(ActionHandlerError::Source);
        }
        Ok(&self.ast)
    }
}

/// Benchmark variant of `evaluate_with_engine` that reuses a program compiled
/// through `CachedActionHandlerProgram::compile`. Admission, per-call engine
/// construction, context shape, limits, resolver registration path, and
/// result decoding are identical; only the per-call compilation is replaced
/// by the bound-program check. Test-only, like the program type.
#[cfg(test)]
pub(crate) fn evaluate_with_cached_program(
    action: &CompiledAction,
    program: &CachedActionHandlerProgram,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
    resolver: Option<EvidenceResolver>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let handler = admit_handler(action, inputs, deadline, resolver.as_ref())?;
    let ast = program.bound_ast(handler)?;
    execute_compiled_handler(
        action,
        handler,
        ast,
        inputs,
        deadline,
        resolver,
        cancellation,
    )
}
