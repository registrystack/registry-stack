// SPDX-License-Identifier: Apache-2.0
//! Pure functions under one pinned, bounded interpreter profile.

use chrono::{DateTime, Datelike, SecondsFormat, TimeDelta, Utc};
use registry_platform_script::rhai::{self as platform, RhaiBaseEngine, RhaiLimits, RhaiProfile};
use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicIteratorPackage, BasicMapPackage,
    BasicStringPackage, LogicPackage, Package,
};
use rhai::{Dynamic, Engine, EvalAltResult, Position, AST, INT};
use serde_json::Value;

use crate::{CoordinatorError, Result};

/// Changing this identity requires a new definition digest.
pub const INTERPRETER_ABI: &str = "coordinator/pure-rhai-1.26.1/v1;raw-arithmetic-logic-string-array-map-iterator-instant;ops=100000;calls=32;expr=64;string=16384;array=256;map=256;source=65536;json=131072;depth=32";

const PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: 100_000,
        call_levels: 32,
        expression_depth: 64,
        modules: 0,
        string_bytes: 16_384,
        array_items: 256,
        map_entries: 256,
    },
    base: RhaiBaseEngine::Raw,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: 65_536,
};

#[derive(Clone)]
pub(crate) struct Functions {
    ast: Option<AST>,
}

impl Functions {
    /// Compile the source for the functions the mappings call, each given
    /// with its step and the authored member that holds it, or report every
    /// refusal.
    pub(crate) fn compile(
        source: &str,
        mappings: &[(&str, &str, &crate::definition::Mapping)],
    ) -> std::result::Result<Self, Vec<CoordinatorError>> {
        if source.len() > PROFILE.maximum_source_bytes {
            return Err(vec![
                failure("function.source_limit").at("functions.rhai", "/")
            ]);
        }
        let mut ast = None;
        let mut findings: Vec<CoordinatorError> = Vec::new();
        // Reference and fields mappings call no function.
        for (step, role, function, arity) in
            mappings
                .iter()
                .filter_map(|(step, role, mapping)| match mapping {
                    crate::definition::Mapping::Function {
                        function,
                        arguments,
                    } => Some((step, role, function, arguments.len())),
                    _ => None,
                })
        {
            let field = format!("steps.{step}.{role}.function");
            let refusal = if arity > 16 {
                CoordinatorError::new(
                    "function.arity",
                    format!(
                        "step {step} passes {} to function {function}; a function takes at most 16",
                        counted(arity, "argument")
                    ),
                )
                .at("workflow.yaml", &field)
                .suggest("Pass at most 16 arguments, or gather values in a fields mapping first.")
            } else {
                match platform::compile_entrypoint(&PROFILE, source, function, &[arity]) {
                    Ok(checked) => {
                        ast.get_or_insert(checked);
                        continue;
                    }
                    Err(platform::RhaiCompileError::SourceBound) => {
                        failure("function.source_limit").at("functions.rhai", "/")
                    }
                    Err(platform::RhaiCompileError::Parse(position)) => {
                        CoordinatorError::new("function.definition", syntax_refusal(source))
                            .at(
                                "functions.rhai",
                                format!(
                                    "line {} column {}",
                                    position.line().unwrap_or(0),
                                    position.position().unwrap_or(0)
                                ),
                            )
                            .suggest(
                                "Correct the named function or syntax position, then rerun check.",
                            )
                    }
                    Err(platform::RhaiCompileError::Entrypoint) => {
                        entrypoint_refusal(source, step, &field, function, arity)
                    }
                }
            };
            if !findings.iter().any(|finding| {
                finding.code == refusal.code
                    && finding.message == refusal.message
                    && finding.field == refusal.field
            }) {
                findings.push(refusal);
            }
        }
        if !findings.is_empty() {
            return Err(findings);
        }
        // A workflow with no mappings still compiles its source; invalid source
        // cannot become valid merely because no current step invokes it.
        if ast.is_none() {
            let engine = platform::build_engine(&PROFILE, None, register_pure_packages);
            ast = Some(
                engine
                    .compile(source)
                    .map_err(|_| vec![failure("function.definition")])?,
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for function in ast
            .as_ref()
            .into_iter()
            .flat_map(|ast| ast.iter_functions())
        {
            if !names.insert(function.name.to_owned()) || names.len() > 128 {
                return Err(vec![failure("function.definition")]);
            }
        }
        Ok(Self { ast })
    }

    /// Call one function. When `synthetic`, a failure also names its kind and
    /// where in functions.rhai it arose, never a value; only offline
    /// scenarios ask for it.
    pub(crate) fn evaluate(
        &self,
        name: &str,
        values: Vec<&Value>,
        synthetic: bool,
    ) -> Result<Value> {
        let arguments = values
            .into_iter()
            .map(|value| {
                check_value(value)?;
                rhai::serde::to_dynamic(value).map_err(|_| failure("function.input"))
            })
            .collect::<Result<Vec<Dynamic>>>()?;
        let engine = platform::build_engine(&PROFILE, None, register_pure_packages);
        let ast = self
            .ast
            .as_ref()
            .ok_or_else(|| failure("function.definition"))?;
        let value =
            platform::call_with_fresh_scope(&engine, ast, name, arguments).map_err(|error| {
                let refusal = failure(match platform::classify_failure(&error) {
                    platform::RhaiFailureCategory::ResourceExhausted => "function.resource_limit",
                    platform::RhaiFailureCategory::Other => "function.execution",
                });
                if synthetic {
                    CoordinatorError {
                        message: format!("function {name} failed: {}", located(name, &error)),
                        ..refusal
                    }
                    .suggest(format!("Correct function {name} in functions.rhai at the line named, or the scenario values it reads."))
                } else {
                    refusal
                }
            })?;
        let value = rhai::serde::from_dynamic(&value).map_err(|_| failure("function.output"))?;
        check_value(&value)?;
        Ok(value)
    }
}

/// The kind of a function failure, the innermost function it arose in and
/// its position there. The interpreter's own message is never used: it may
/// repeat a thrown value or an argument.
fn located(name: &str, error: &EvalAltResult) -> String {
    let mut function = name;
    let mut error = error;
    while let EvalAltResult::ErrorInFunctionCall(called, _, inner, _) = error {
        function = called;
        error = inner;
    }
    let kind = match error {
        EvalAltResult::ErrorRuntime(..) => "an error was thrown",
        EvalAltResult::ErrorPropertyNotFound(..) | EvalAltResult::ErrorDotExpr(..) => {
            "a property is missing"
        }
        EvalAltResult::ErrorVariableNotFound(..) => "a variable is undefined",
        EvalAltResult::ErrorFunctionNotFound(..) => "no function matches a call",
        EvalAltResult::ErrorMismatchDataType(..) | EvalAltResult::ErrorMismatchOutputType(..) => {
            "a value has the wrong type"
        }
        EvalAltResult::ErrorIndexingType(..) => "a value cannot be indexed",
        EvalAltResult::ErrorIndexNotFound(..) => "an index is missing",
        EvalAltResult::ErrorArrayBounds(..)
        | EvalAltResult::ErrorStringBounds(..)
        | EvalAltResult::ErrorBitFieldBounds(..) => "an index is out of bounds",
        EvalAltResult::ErrorArithmetic(..) => "an arithmetic operation failed",
        EvalAltResult::ErrorFor(..) => "a value cannot be iterated",
        EvalAltResult::ErrorAssignmentToConstant(..)
        | EvalAltResult::ErrorNonPureMethodCallOnConstant(..) => "a constant was changed",
        EvalAltResult::ErrorTooManyOperations(..)
        | EvalAltResult::ErrorTooManyVariables(..)
        | EvalAltResult::ErrorTooManyModules(..)
        | EvalAltResult::ErrorStackOverflow(..)
        | EvalAltResult::ErrorDataTooLarge(..)
        | EvalAltResult::ErrorTerminated(..) => "a resource limit was reached",
        _ => "the interpreter refused an operation",
    };
    let position = error.position();
    match (position.line(), position.position()) {
        (Some(line), Some(column)) => {
            format!("{kind} in function {function} at line {line}, column {column}")
        }
        (Some(line), None) => format!("{kind} in function {function} at line {line}"),
        _ => format!("{kind} in function {function}"),
    }
}

/// Why `function` is not one public entry point taking `arity` arguments:
/// placed at the calling step, or in functions.rhai when a name is declared
/// twice there.
fn entrypoint_refusal(
    source: &str,
    step: &str,
    field: &str,
    function: &str,
    arity: usize,
) -> CoordinatorError {
    let declared = platform::build_engine(&PROFILE, None, |_| {})
        .compile(source)
        .map(|ast| {
            ast.iter_functions()
                .map(|declared| {
                    (
                        declared.name.to_owned(),
                        declared.params.len(),
                        declared.access == rhai::FnAccess::Public,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    if let Some((twice, ..)) = declared
        .iter()
        .find(|(name, ..)| !seen.insert(name.as_str()))
    {
        return CoordinatorError::new(
            "function.definition",
            format!("functions.rhai declares function {twice} more than once; function names cannot be overloaded"),
        )
        .at("functions.rhai", format!("function {twice}"))
        .suggest(format!("Keep one definition of function {twice} in functions.rhai, and give the others their own names."));
    }
    let refusal = |message: String, action: String| {
        CoordinatorError::new("function.definition", message)
            .at("workflow.yaml", field)
            .suggest(action)
    };
    match declared.iter().find(|(name, ..)| name == function) {
        None => {
            let mut public = declared
                .iter()
                .filter(|(.., public)| *public)
                .map(|(name, ..)| name.as_str())
                .collect::<Vec<_>>();
            public.sort_unstable();
            refusal(
                format!(
                    "step {step} calls function {function}, which functions.rhai does not declare; it declares {}",
                    crate::definition::listed(public)
                ),
                format!(
                    "Name one of the declared functions, or add fn {function} with {} to functions.rhai.",
                    counted(arity, "parameter")
                ),
            )
        }
        Some((_, _, false)) => refusal(
            format!("step {step} calls function {function}, which functions.rhai declares private"),
            format!("Remove private from function {function} in functions.rhai."),
        ),
        Some((_, parameters, true)) => refusal(
            format!(
                "step {step} passes {} to function {function}, which takes {}",
                counted(arity, "argument"),
                counted(*parameters, "parameter")
            ),
            format!(
                "Pass {} from step {step}, or change function {function} to take {}.",
                counted(*parameters, "argument"),
                counted(arity, "parameter")
            ),
        ),
    }
}

/// A count with its noun, such as 1 argument or 2 parameters.
fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// The parser's own reason for refusing authored source, which names source
/// text and never a run value.
fn syntax_refusal(source: &str) -> String {
    let reason = platform::build_engine(&PROFILE, None, |_| {})
        .compile(source)
        .err()
        .map(|error| format!(": {}", error.err_type()))
        .unwrap_or_default();
    format!("function source has invalid or disabled syntax{reason}")
}

/// Bound structured values before conversion and after execution as well as
/// the engine's individual container limits. Errors never render the value.
pub(crate) fn check_value(value: &Value) -> Result<()> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if depth > 32 || *nodes > 4096 {
            return false;
        }
        match value {
            Value::Array(items) => {
                items.len() <= 256 && items.iter().all(|v| walk(v, depth + 1, nodes))
            }
            Value::Object(items) => {
                items.len() <= 256
                    && items
                        .iter()
                        .all(|(k, v)| k.len() <= 16384 && walk(v, depth + 1, nodes))
            }
            Value::String(text) => text.len() <= 16384,
            _ => true,
        }
    }
    if !walk(value, 0, &mut 0) {
        return Err(failure("function.value_limit"));
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(value)
        .map_err(|_| failure("function.json"))?;
    if bytes.len() > 131_072 {
        return Err(failure("function.value_limit"));
    }
    Ok(())
}

fn failure(code: &'static str) -> CoordinatorError {
    CoordinatorError::new(code, match code {
        "function.resource_limit" => "the function exceeded its operation, call-depth or value-size budget",
        "function.value_limit" => "the structured value exceeded its size or depth budget",
        "function.execution" => "the function could not evaluate its supplied values",
        "function.source_limit" => "functions.rhai exceeds the 65536-byte source budget",
        _ => "the pure function boundary refused the definition or value",
    }).suggest("Inspect the named mapping and reduce bounded work or correct its declared arguments; values are omitted.")
}

fn register_pure_packages(engine: &mut Engine) {
    ArithmeticPackage::new().register_into_engine(engine);
    LogicPackage::new().register_into_engine(engine);
    BasicStringPackage::new().register_into_engine(engine);
    BasicArrayPackage::new().register_into_engine(engine);
    BasicMapPackage::new().register_into_engine(engine);
    BasicIteratorPackage::new().register_into_engine(engine);
    engine
        .register_fn("add_seconds", add_seconds)
        .register_fn("seconds_between", seconds_between);
}

/// The instant moved by a signed number of seconds, written in UTC. The result
/// must keep the four-digit year RFC 3339 can write, which bounds `seconds`.
fn add_seconds(instant: &str, seconds: INT) -> std::result::Result<String, Box<EvalAltResult>> {
    let delta = TimeDelta::try_seconds(seconds).ok_or_else(instant_refused)?;
    let moved = parse_instant(instant)?
        .checked_add_signed(delta)
        .filter(|moved| (0..=9999).contains(&moved.year()))
        .ok_or_else(instant_refused)?;
    Ok(moved.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

/// Whole seconds from the first instant to the second, truncated toward zero.
/// Two RFC 3339 instants are at most about 3.2e11 seconds apart.
fn seconds_between(first: &str, second: &str) -> std::result::Result<INT, Box<EvalAltResult>> {
    Ok(parse_instant(second)?
        .signed_duration_since(parse_instant(first)?)
        .num_seconds())
}

/// An RFC 3339 date-time with its offset. The refusal names no value.
fn parse_instant(text: &str) -> std::result::Result<DateTime<Utc>, Box<EvalAltResult>> {
    DateTime::parse_from_rfc3339(text)
        .map(|instant| instant.with_timezone(&Utc))
        .map_err(|_| instant_refused())
}

fn instant_refused() -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime("an instant is outside RFC 3339".into(), Position::NONE).into()
}

pub(crate) fn limits() -> Value {
    serde_json::json!({"operations":PROFILE.limits.operations,"callLevels":PROFILE.limits.call_levels,
        "expressionDepth":PROFILE.limits.expression_depth,"stringBytes":PROFILE.limits.string_bytes,
        "arrayItems":PROFILE.limits.array_items,"mapEntries":PROFILE.limits.map_entries,
        "sourceBytes":PROFILE.maximum_source_bytes,"jsonBytes":131072,"jsonDepth":32,"jsonNodes":4096,
        "maximumArguments":16,"maximumFunctions":128,"modules":0})
}
