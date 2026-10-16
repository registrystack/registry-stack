// SPDX-License-Identifier: Apache-2.0
//! Pure functions under one pinned, bounded interpreter profile.

use crate::definition::{compile_schema, FunctionDefinition};
use chrono::{DateTime, Datelike, SecondsFormat, TimeDelta, Utc};
use registry_platform_script::rhai::{self as platform, RhaiBaseEngine, RhaiLimits, RhaiProfile};
use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicIteratorPackage, BasicMapPackage,
    BasicStringPackage, LogicPackage, Package,
};
use rhai::{Engine, EvalAltResult, Position, AST, INT};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{CoordinatorError, Result};

/// Changing this identity requires a new Workflow revision.
pub const PURE_PROFILE: &str = "coordinator/bounded-pure/v1";

pub const INTERPRETER_ABI: &str = "coordinator/pure-rhai-1.26.1/v1;named-input-object;raw-arithmetic-logic-string-array-map-iterator-instant;ops=100000;calls=32;expr=64;string=16384;array=256;map=256;source=65536;json=131072;depth=32";

pub(crate) const MAXIMUM_FUNCTION_OPERATIONS: u32 = 100_000;
pub(crate) const MAXIMUM_FUNCTION_CALL_LEVELS: u32 = 32;
pub(crate) const MAXIMUM_FUNCTION_EXPRESSION_DEPTH: u32 = 64;
pub(crate) const MAXIMUM_FUNCTION_STRING_BYTES: u32 = 16_384;
pub(crate) const MAXIMUM_FUNCTION_ARRAY_ITEMS: u32 = 256;
pub(crate) const MAXIMUM_FUNCTION_MAP_ENTRIES: u32 = 256;
pub(crate) const MAXIMUM_FUNCTION_SOURCE_BYTES: u32 = 65_536;

pub(crate) const MAXIMUM_VALUE_BYTES: usize = 131_072;
pub(crate) const MAXIMUM_VALUE_DEPTH: usize = 32;
pub(crate) const MAXIMUM_VALUE_NODES: usize = 4_096;
pub(crate) const MAXIMUM_VALUE_ARRAY_ITEMS: usize = 256;
pub(crate) const MAXIMUM_VALUE_OBJECT_MEMBERS: usize = 256;
pub(crate) const MAXIMUM_VALUE_STRING_BYTES: usize = 16_384;

const PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: MAXIMUM_FUNCTION_OPERATIONS as u64,
        call_levels: MAXIMUM_FUNCTION_CALL_LEVELS as usize,
        expression_depth: MAXIMUM_FUNCTION_EXPRESSION_DEPTH as usize,
        modules: 0,
        string_bytes: MAXIMUM_FUNCTION_STRING_BYTES as usize,
        array_items: MAXIMUM_FUNCTION_ARRAY_ITEMS as usize,
        map_entries: MAXIMUM_FUNCTION_MAP_ENTRIES as usize,
    },
    base: RhaiBaseEngine::Raw,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: MAXIMUM_FUNCTION_SOURCE_BYTES as usize,
};

#[derive(Clone)]
pub(crate) struct Functions {
    entries: BTreeMap<String, CompiledFunction>,
}

#[derive(Clone)]
struct CompiledFunction {
    definition: FunctionDefinition,
    ast: AST,
    input: std::sync::Arc<jsonschema::JSONSchema>,
    output: std::sync::Arc<jsonschema::JSONSchema>,
}

fn profile(function: &FunctionDefinition) -> RhaiProfile {
    RhaiProfile {
        limits: RhaiLimits {
            operations: function.limits.operations,
            call_levels: function.limits.call_levels,
            expression_depth: function.limits.expression_depth,
            modules: 0,
            string_bytes: function.limits.string_bytes,
            array_items: function.limits.array_items,
            map_entries: function.limits.map_entries,
        },
        maximum_source_bytes: function.limits.source_bytes,
        ..PROFILE
    }
}

impl Functions {
    pub(crate) fn compile(
        sources: &BTreeMap<String, String>,
        definitions: &BTreeMap<String, FunctionDefinition>,
    ) -> std::result::Result<Self, Vec<CoordinatorError>> {
        let mut entries = BTreeMap::new();
        let mut findings = Vec::new();
        for (name, function) in definitions {
            let result = (|| {
                let source = sources
                    .get(&function.source)
                    .ok_or_else(|| failure("function.definition"))?;
                let limits = &function.limits;
                let ceiling = crate::definition::FunctionLimits::default();
                if function.runtime != "rhai"
                    || !function.capabilities.is_empty()
                    || function.profile != PURE_PROFILE
                    || function.abi != INTERPRETER_ABI
                    || limits.operations == 0
                    || limits.operations > ceiling.operations
                    || limits.call_levels == 0
                    || limits.call_levels > ceiling.call_levels
                    || limits.expression_depth == 0
                    || limits.expression_depth > ceiling.expression_depth
                    || limits.string_bytes == 0
                    || limits.string_bytes > ceiling.string_bytes
                    || limits.array_items == 0
                    || limits.array_items > ceiling.array_items
                    || limits.map_entries == 0
                    || limits.map_entries > ceiling.map_entries
                    || limits.source_bytes == 0
                    || limits.source_bytes > ceiling.source_bytes
                    || function.inputs.len() > 16
                {
                    return Err(failure("function.limits")
                        .at("workflow.yaml", format!("/functions/{name}/limits")));
                }
                let ast = platform::compile_entrypoint(&profile(function), source, &function.entrypoint, &[1])
                    .map_err(|error| match error {
                        platform::RhaiCompileError::SourceBound => failure("function.source_limit").at(&function.source, "/"),
                        platform::RhaiCompileError::Parse(position) => CoordinatorError::new("function.definition", syntax_refusal(source))
                            .at(&function.source, format!("line {} column {}", position.line().unwrap_or(0), position.position().unwrap_or(0)))
                            .suggest("Correct the named Function source syntax and rerun check."),
                        platform::RhaiCompileError::Entrypoint => CoordinatorError::new("function.definition", "the Function entrypoint must name one public Rhai function taking one named-input object")
                            .at("workflow.yaml", format!("/functions/{name}/entrypoint"))
                            .suggest("Declare one public function with exactly one parameter for its named input object."),
                    })?;
                let mut names = std::collections::BTreeSet::new();
                if ast
                    .iter_functions()
                    .any(|function| !names.insert(function.name.to_owned()))
                    || names.len() > 128
                {
                    return Err(failure("function.definition").at(&function.source, "/"));
                }
                let properties = function
                    .inputs
                    .iter()
                    .map(|(name, schema)| {
                        crate::authoring::embed_schema(
                            schema,
                            &format!("/properties/{}", name.replace('~', "~0").replace('/', "~1")),
                        )
                        .map(|schema| (name.clone(), schema))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                let input_schema = serde_json::json!({"type":"object","additionalProperties":false,
                    "properties":properties,"required":function.inputs.keys().collect::<Vec<_>>()});
                let input = std::sync::Arc::new(compile_schema(&input_schema)?);
                let output = std::sync::Arc::new(compile_schema(&function.output)?);
                let revision = revision(function, source)?;
                if function.revision != revision {
                    return Err(failure("function.revision")
                        .at("workflow.yaml", format!("/functions/{name}")));
                }
                Ok(CompiledFunction {
                    definition: function.clone(),
                    ast,
                    input,
                    output,
                })
            })();
            match result {
                Ok(compiled) => {
                    entries.insert(name.clone(), compiled);
                }
                Err(error) => findings.push(error),
            }
        }
        if findings.is_empty() {
            Ok(Self { entries })
        } else {
            Err(findings)
        }
    }

    pub(crate) fn evaluate(&self, name: &str, inputs: &Value, synthetic: bool) -> Result<Value> {
        let function = self
            .entries
            .get(name)
            .ok_or_else(|| failure("function.definition"))?;
        check_value(inputs)?;
        if !function.input.is_valid(inputs) {
            return Err(contract_failure(
                name,
                "function.input",
                &function.input,
                inputs,
                synthetic,
            ));
        }
        let arguments =
            vec![rhai::serde::to_dynamic(inputs).map_err(|_| failure("function.input"))?];
        let engine =
            platform::build_engine(&profile(&function.definition), None, register_pure_packages);
        let value = platform::call_with_fresh_scope(&engine, &function.ast, &function.definition.entrypoint, arguments)
            .map_err(|error| {
                let refusal = failure(match platform::classify_failure(&error) {
                    platform::RhaiFailureCategory::ResourceExhausted => "function.resource_limit",
                    platform::RhaiFailureCategory::Other => "function.execution",
                });
                if synthetic { CoordinatorError { message: format!("function {name} failed: {}", located(&function.definition.entrypoint, &error)), ..refusal }
                    .suggest(format!("Correct Function {name} in {} at the named position, or correct its synthetic inputs.", function.definition.source)) }
                else { refusal }
            })?;
        let value = rhai::serde::from_dynamic(&value).map_err(|_| failure("function.output"))?;
        check_value(&value)?;
        if !function.output.is_valid(&value) {
            return Err(contract_failure(
                name,
                "function.output",
                &function.output,
                &value,
                synthetic,
            ));
        }
        Ok(value)
    }
}

fn contract_failure(
    name: &str,
    code: &'static str,
    schema: &jsonschema::JSONSchema,
    value: &Value,
    synthetic: bool,
) -> CoordinatorError {
    let refusal = failure(code);
    if !synthetic {
        return refusal;
    }
    let role = if code == "function.input" {
        "named inputs"
    } else {
        "output"
    };
    let rule = crate::definition::schema_refusal(schema, value).unwrap_or_default();
    CoordinatorError {message:format!("function {name} returned a value of class {}; its declared {role} schema refuses it{rule}",crate::definition::class(value)),..refusal}
        .suggest(format!("Correct Function {name} or its synthetic input mappings to satisfy the named signature rule."))
}

pub(crate) fn revision(function: &FunctionDefinition, source: &str) -> Result<String> {
    let semantic = serde_json::json!({"runtime":function.runtime,"profile":function.profile,"capabilities":function.capabilities,"abi":function.abi,"entrypoint":function.entrypoint,
        "inputs":function.inputs.iter().map(|(name,schema)| (name,crate::definition::semantic_schema(schema))).collect::<BTreeMap<_,_>>(),"output":crate::definition::semantic_schema(&function.output),"limits":function.limits,"valueLimits":value_limits(),"sourceDigest":registry_platform_config::sha256_uri(source.as_bytes())});
    let bytes = registry_platform_canonical_json::canonicalize_json(&semantic)
        .map_err(|_| failure("function.definition"))?;
    Ok(registry_platform_config::sha256_uri(&bytes))
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
        if depth > MAXIMUM_VALUE_DEPTH || *nodes > MAXIMUM_VALUE_NODES {
            return false;
        }
        match value {
            Value::Array(items) => {
                items.len() <= MAXIMUM_VALUE_ARRAY_ITEMS
                    && items.iter().all(|v| walk(v, depth + 1, nodes))
            }
            Value::Object(items) => {
                items.len() <= MAXIMUM_VALUE_OBJECT_MEMBERS
                    && items.iter().all(|(k, v)| {
                        k.len() <= MAXIMUM_VALUE_STRING_BYTES && walk(v, depth + 1, nodes)
                    })
            }
            Value::String(text) => text.len() <= MAXIMUM_VALUE_STRING_BYTES,
            _ => true,
        }
    }
    if !walk(value, 0, &mut 0) {
        return Err(failure("function.value_limit"));
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(value)
        .map_err(|_| failure("function.json"))?;
    if bytes.len() > MAXIMUM_VALUE_BYTES {
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

/// Structured JSON custody limits, shared by every host Operation boundary.
/// These are distinct from a pure Function's narrowed interpreter limits.
pub(crate) fn value_limits() -> Value {
    serde_json::json!({
        "maximumBytes": MAXIMUM_VALUE_BYTES,
        "maximumDepth": MAXIMUM_VALUE_DEPTH,
        "maximumNodes": MAXIMUM_VALUE_NODES,
        "maximumArrayItems": MAXIMUM_VALUE_ARRAY_ITEMS,
        "maximumObjectMembers": MAXIMUM_VALUE_OBJECT_MEMBERS,
        "maximumStringBytes": MAXIMUM_VALUE_STRING_BYTES,
    })
}

pub(crate) fn limits() -> Value {
    serde_json::json!({"operations":PROFILE.limits.operations,"callLevels":PROFILE.limits.call_levels,
        "expressionDepth":PROFILE.limits.expression_depth,"stringBytes":PROFILE.limits.string_bytes,
        "arrayItems":PROFILE.limits.array_items,"mapEntries":PROFILE.limits.map_entries,
        "sourceBytes":PROFILE.maximum_source_bytes,"jsonBytes":MAXIMUM_VALUE_BYTES,"jsonDepth":MAXIMUM_VALUE_DEPTH,"jsonNodes":MAXIMUM_VALUE_NODES,
        "maximumInputs":16,"maximumFunctions":128,"modules":0})
}
