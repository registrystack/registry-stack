// SPDX-License-Identifier: Apache-2.0
//! Pure functions under one pinned, bounded interpreter profile.

use crate::definition::{compile_schema, FunctionDefinition};
use chrono::{DateTime, Datelike, SecondsFormat, TimeDelta, Utc};
use registry_platform_script::rhai::{self as platform, RhaiBaseEngine, RhaiLimits, RhaiProfile};
use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicIteratorPackage, BasicMapPackage,
    BasicStringPackage, LogicPackage, MoreStringPackage, Package,
};
use rhai::{
    ASTNode, Dynamic, Engine, EvalAltResult, Expr, FnPtr, ImmutableString, NativeCallContext,
    Position, Stmt, AST, INT,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::{CoordinatorError, Result};

/// Changing this identity requires a new Workflow revision.
pub const PURE_PROFILE: &str = "coordinator/bounded-pure/v1";

pub const INTERPRETER_ABI: &str = "coordinator/pure-rhai-1.27.0/v2;named-input-object;raw-arithmetic-logic-string-more-string-deterministic-math-array-map-iterator-instant;ops=100000;calls=32;expr=64;string=16384;array=256;map=256;source=65536;json=131072;depth=32";

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
        let mut reported = BTreeSet::new();
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
                    // Functions share one source, so each walk finds the same
                    // calls; a call is reported once, at its position.
                    let unknown = unknown_calls(&compiled);
                    if unknown.is_empty() {
                        entries.insert(name.clone(), compiled);
                    }
                    for finding in unknown {
                        if reported.insert((finding.file.clone(), finding.field.clone())) {
                            findings.push(finding);
                        }
                    }
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
        if holds_non_finite(&value, 0) {
            let refusal = failure("function.execution");
            return Err(if synthetic {
                CoordinatorError { message: format!("function {name} returned NaN or an infinite number, which has no JSON form"), ..refusal }
                    .suggest(format!("Correct Function {name} so it never divides by zero or takes the square root of a negative number; test with is_finite first."))
            } else {
                refusal
            });
        }
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
    MoreStringPackage::new().register_into_engine(engine);
    register_deterministic_math(engine);
    BasicArrayPackage::new().register_into_engine(engine);
    BasicMapPackage::new().register_into_engine(engine);
    BasicIteratorPackage::new().register_into_engine(engine);
    // The package `replace` builds its whole result before the engine's string
    // limit can refuse it, so these overloads take its place and check first.
    engine
        .register_fn("replace", replace_text)
        .register_fn("replace", replace_text_with_char)
        .register_fn("replace", replace_char_with_text)
        .register_fn("replace", replace_char);
    // The package `pad` with a string never ends when the padding is empty, so
    // this overload refuses that and checks the size before it builds.
    engine.register_fn("pad", pad_text);
    engine
        .register_fn("add_seconds", add_seconds)
        .register_fn("seconds_between", seconds_between);
}

/// The floating-point and number-parsing helpers whose result is the same on
/// every host: IEEE 754 arithmetic (`sqrt` is correctly rounded), rounding,
/// parsing and conversion. The package's libm functions (`sin`, `exp`, `ln`,
/// `hypot` and the like) are left out because their last digits depend on the
/// host's math library, and Function results are recomputed when waits replay.
fn register_deterministic_math(engine: &mut Engine) {
    engine
        .register_fn("PI", || std::f64::consts::PI)
        .register_fn("E", || std::f64::consts::E)
        .register_fn("sqrt", |x: f64| x.sqrt())
        .register_fn("to_degrees", |x: f64| x.to_degrees())
        .register_fn("to_radians", |x: f64| x.to_radians())
        .register_fn("floor", |x: f64| x.floor())
        .register_fn("ceiling", |x: f64| x.ceil())
        .register_fn("round", |x: f64| x.round())
        .register_fn("int", |x: f64| x.trunc())
        .register_fn("fraction", |x: f64| x.fract())
        .register_fn("is_nan", |x: f64| x.is_nan())
        .register_fn("is_finite", |x: f64| x.is_finite())
        .register_fn("is_infinite", |x: f64| x.is_infinite())
        .register_get("floor", |x: &mut f64| x.floor())
        .register_get("ceiling", |x: &mut f64| x.ceil())
        .register_get("round", |x: &mut f64| x.round())
        .register_get("int", |x: &mut f64| x.trunc())
        .register_get("fraction", |x: &mut f64| x.fract())
        .register_get("is_nan", |x: &mut f64| x.is_nan())
        .register_get("is_finite", |x: &mut f64| x.is_finite())
        .register_get("is_infinite", |x: &mut f64| x.is_infinite())
        .register_fn("to_float", |x: f64| x)
        .register_fn("to_float", |x: INT| x as f64)
        .register_fn("to_int", |x: INT| x)
        .register_fn("to_int", |x: char| x as INT)
        .register_fn("to_int", float_to_int)
        .register_fn("parse_float", parse_float)
        .register_fn("parse_int", |text: &str| parse_int(text, 10))
        .register_fn("parse_int", parse_int);
}

fn arithmetic_error(message: String) -> Box<EvalAltResult> {
    EvalAltResult::ErrorArithmetic(message, Position::NONE).into()
}

fn float_to_int(x: f64) -> std::result::Result<INT, Box<EvalAltResult>> {
    if x.is_nan() || x > INT::MAX as f64 || x < INT::MIN as f64 {
        return Err(arithmetic_error("Integer overflow: to_int".to_owned()));
    }
    Ok(x.trunc() as INT)
}

fn parse_float(text: &str) -> std::result::Result<f64, Box<EvalAltResult>> {
    text.trim()
        .parse::<f64>()
        .map_err(|_| arithmetic_error("Error parsing floating-point number".to_owned()))
}

fn parse_int(text: &str, radix: INT) -> std::result::Result<INT, Box<EvalAltResult>> {
    let radix = u32::try_from(radix)
        .ok()
        .filter(|radix| (2..=36).contains(radix))
        .ok_or_else(|| arithmetic_error("Invalid radix".to_owned()))?;
    INT::from_str_radix(text.trim(), radix)
        .map_err(|_| arithmetic_error("Error parsing integer number".to_owned()))
}

/// Whether a result holds a NaN or infinite float. JSON has no such number, so
/// converting one would silently turn it into `null`. Nesting deeper than the
/// value limit is not searched: `check_value` refuses it anyway.
fn holds_non_finite(value: &Dynamic, depth: usize) -> bool {
    if let Ok(number) = value.as_float() {
        return !number.is_finite();
    }
    if depth > MAXIMUM_VALUE_DEPTH {
        return false;
    }
    if let Some(items) = value.read_lock::<rhai::Array>() {
        return items.iter().any(|item| holds_non_finite(item, depth + 1));
    }
    if let Some(members) = value.read_lock::<rhai::Map>() {
        return members
            .values()
            .any(|member| holds_non_finite(member, depth + 1));
    }
    false
}

/// The byte length of `string.replace(find, with)`, worked out without
/// building the result.
fn replaced_len(string: &str, find: &str, with: &str) -> usize {
    let matches = string.matches(find).count();
    string
        .len()
        .saturating_sub(matches.saturating_mul(find.len()))
        .saturating_add(matches.saturating_mul(with.len()))
}

fn replace_checked(
    context: &NativeCallContext,
    string: &mut ImmutableString,
    find: &str,
    with: &str,
) -> std::result::Result<(), Box<EvalAltResult>> {
    if string.is_empty() {
        return Ok(());
    }
    let limit = context.engine().max_string_size();
    if limit > 0 && replaced_len(string, find, with) > limit {
        return Err(EvalAltResult::ErrorDataTooLarge(
            "the string replace would build".into(),
            Position::NONE,
        )
        .into());
    }
    *string = string.replace(find, with).into();
    Ok(())
}

fn replace_text(
    context: NativeCallContext,
    string: &mut ImmutableString,
    find: &str,
    with: &str,
) -> std::result::Result<(), Box<EvalAltResult>> {
    replace_checked(&context, string, find, with)
}

fn replace_text_with_char(
    context: NativeCallContext,
    string: &mut ImmutableString,
    find: &str,
    with: char,
) -> std::result::Result<(), Box<EvalAltResult>> {
    replace_checked(&context, string, find, &with.to_string())
}

fn replace_char_with_text(
    context: NativeCallContext,
    string: &mut ImmutableString,
    find: char,
    with: &str,
) -> std::result::Result<(), Box<EvalAltResult>> {
    replace_checked(&context, string, &find.to_string(), with)
}

fn replace_char(
    context: NativeCallContext,
    string: &mut ImmutableString,
    find: char,
    with: char,
) -> std::result::Result<(), Box<EvalAltResult>> {
    replace_checked(&context, string, &find.to_string(), &with.to_string())
}

/// The byte length of `string` padded with `padding` up to `length`
/// characters, worked out without building the result. `None` when no padding
/// is needed.
fn padded_len(string: &str, length: usize, padding: &str) -> Option<usize> {
    let missing = length
        .checked_sub(string.chars().count())
        .filter(|missing| *missing > 0)?;
    let padding_chars = padding.chars().count();
    let whole = missing / padding_chars;
    let partial = padding
        .chars()
        .take(missing % padding_chars)
        .map(char::len_utf8)
        .sum::<usize>();
    Some(
        string
            .len()
            .saturating_add(whole.saturating_mul(padding.len()))
            .saturating_add(partial),
    )
}

/// `string.pad(length, padding)`: the package behaviour for non-empty padding,
/// refusing empty padding and a result over the string limit before building.
fn pad_text(
    context: NativeCallContext,
    string: &mut ImmutableString,
    length: INT,
    padding: &str,
) -> std::result::Result<(), Box<EvalAltResult>> {
    let Ok(length) = usize::try_from(length) else {
        // A negative length asks for no padding.
        return Ok(());
    };
    if padding.is_empty() {
        return Err(EvalAltResult::ErrorRuntime(
            "pad needs a padding string that is not empty".into(),
            Position::NONE,
        )
        .into());
    }
    let Some(built) = padded_len(string, length, padding) else {
        return Ok(());
    };
    let limit = context.engine().max_string_size();
    if limit > 0 && built > limit {
        return Err(EvalAltResult::ErrorDataTooLarge(
            "the string pad would build".into(),
            Position::NONE,
        )
        .into());
    }
    let missing = length - string.chars().count();
    let mut padded = String::with_capacity(built);
    padded.push_str(string);
    padded.extend(padding.chars().cycle().take(missing));
    *string = padded.into();
    Ok(())
}

/// Calls the interpreter answers itself, so its function table does not list
/// them.
const INTERPRETER_CALLS: [&str; 7] = [
    "Fn",
    "call",
    "curry",
    "is_def_fn",
    "is_def_var",
    "is_shared",
    "type_of",
];

/// The names a Function may call: every callable the pure profile registers,
/// listed once from a real engine so the list cannot drift from what runs.
/// Operators, property accessors and the symbols the profile disables are not
/// calls an author writes by name.
pub(crate) fn helpers() -> &'static BTreeSet<String> {
    static HELPERS: OnceLock<BTreeSet<String>> = OnceLock::new();
    HELPERS.get_or_init(|| {
        let registered = platform::build_engine(&PROFILE, None, register_pure_packages)
            .collect_fn_metadata(
                None,
                |info| {
                    let name = info.metadata.name.as_str();
                    (rhai::is_valid_identifier(name) && !PROFILE.disabled_symbols.contains(&name))
                        .then(|| name.to_owned())
                },
                true,
            )
            .into_iter();
        registered
            .chain(INTERPRETER_CALLS.iter().map(|name| (*name).to_owned()))
            .collect()
    })
}

/// Array methods that take a function by value or by name. A string literal
/// given to one of them names a Function to call. `index_of` and `contains`
/// are left out: they search for the string.
const CALLBACK_METHODS: [&str; 16] = [
    "for_each",
    "map",
    "filter",
    "find",
    "find_map",
    "some",
    "all",
    "dedup",
    "reduce",
    "reduce_rev",
    "sort",
    "drain",
    "retain",
    "zip",
    "order",
    "order_by",
];

/// Calls that take a function name as their first argument.
const NAMING_CALLS: [&str; 2] = ["Fn", "is_def_fn"];

/// One finding for each call, in `name`'s source, to a name that is neither a
/// profile helper nor a function the source defines. Calls are matched by
/// name alone, so a wrong argument count still fails when the Function runs.
/// A string literal given to `Fn`, `is_def_fn` or an array method such as
/// `map` is read as a function name. A method call is skipped when the source
/// also uses its name as a map key or property, since it may call a function
/// pointer stored there. The engine still refuses an unknown name at run time.
fn unknown_calls(function: &CompiledFunction) -> Vec<CoordinatorError> {
    let defined = function
        .ast
        .iter_functions()
        .map(|defined| defined.name.to_owned())
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    let mut calls = Vec::new();
    let mut named = Vec::new();
    function.ast.walk(&mut |path| {
        match path.last() {
            Some(ASTNode::Expr(Expr::Map(map, _))) => {
                keys.extend(map.0.iter().map(|(key, _)| key.name.to_string()));
            }
            // The optimizer folds `Fn("name")` and map literals made of
            // constants into constants, so their names are read from the value.
            Some(ASTNode::Expr(Expr::DynamicConstant(value, position))) => {
                collect_constant(value, *position, &mut keys, &mut named);
            }
            Some(ASTNode::Expr(Expr::Property(property, _))) => {
                keys.insert(property.2.to_string());
            }
            Some(ASTNode::Expr(Expr::Index(index, ..))) => {
                if let Expr::StringConstant(key, _) = &index.rhs {
                    keys.insert(key.to_string());
                }
            }
            // A call used as a statement (a function's tail expression, or a
            // call whose result is dropped) is a `Stmt::FnCall`, not an
            // `Expr::FnCall`.
            Some(ASTNode::Expr(Expr::FnCall(call, position))) => {
                collect_call(call, *position, false, &mut calls, &mut named);
            }
            Some(ASTNode::Expr(Expr::MethodCall(call, position))) => {
                collect_call(call, *position, true, &mut calls, &mut named);
            }
            Some(ASTNode::Stmt(Stmt::FnCall(call, position))) => {
                collect_call(call, *position, false, &mut calls, &mut named);
            }
            _ => {}
        }
        true
    });
    let mut calls = calls
        .into_iter()
        .filter(|(callee, _, is_method)| !(*is_method && keys.contains(callee)))
        .map(|(callee, position, _)| (callee, position))
        .filter(|(callee, _)| !helpers().contains(callee) && !defined.contains(callee))
        .collect::<Vec<_>>();
    calls.extend(
        named
            .into_iter()
            .filter(|(callee, _)| !helpers().contains(callee) && !defined.contains(callee)),
    );
    calls
        .into_iter()
        .map(|(callee, position)| {
            let location = match (position.line(), position.position()) {
                (Some(line), Some(column)) => format!("line {line} column {column}"),
                _ => "/".to_owned(),
            };
            CoordinatorError::new(
                "function.unknown-call",
                format!(
                    "`{callee}` is not available: it is neither a helper of {PURE_PROFILE} nor a function defined in {}",
                    function.definition.source
                ),
            )
            .at(&function.definition.source, location)
            .suggest("Call a listed helper, such as trim, split and starts_with for strings or parse_int and abs for numbers, or define the function in the same source; `coordinatorctl explain functions` lists every helper.")
        })
        .collect()
}

/// Records a call's own name (with whether it is a method call) and any string
/// literal it passes as a function name.
fn collect_call(
    call: &rhai::FnCallExpr,
    position: Position,
    is_method: bool,
    calls: &mut Vec<(String, Position, bool)>,
    named: &mut Vec<(String, Position)>,
) {
    let callee = call.name.as_str();
    if call.op_token.is_none() && !call.is_qualified() {
        calls.push((callee.to_owned(), position, is_method));
    }
    // The argument after a `reduce` callback is its initial value.
    let literals = if is_method && matches!(callee, "reduce" | "reduce_rev") {
        call.args.first().into_iter().collect()
    } else if is_method && CALLBACK_METHODS.contains(&callee) {
        call.args.iter().collect::<Vec<_>>()
    } else if !is_method && NAMING_CALLS.contains(&callee) {
        call.args.first().into_iter().collect()
    } else {
        Vec::new()
    };
    for argument in literals {
        if let Expr::StringConstant(name, _) = argument {
            named.push((name.to_string(), position));
        }
    }
}

/// Reads the function names and map keys held in a constant the optimizer
/// folded: a function pointer, or a map or array holding some.
fn collect_constant(
    value: &Dynamic,
    position: Position,
    keys: &mut BTreeSet<String>,
    named: &mut Vec<(String, Position)>,
) {
    if let Some(pointer) = value.read_lock::<FnPtr>() {
        named.push((pointer.fn_name().to_owned(), position));
    } else if let Some(map) = value.read_lock::<rhai::Map>() {
        for (key, entry) in map.iter() {
            keys.insert(key.to_string());
            collect_constant(entry, position, keys, named);
        }
    } else if let Some(array) = value.read_lock::<rhai::Array>() {
        for entry in array.iter() {
            collect_constant(entry, position, keys, named);
        }
    }
}

/// Behaviour of the helpers that surprises authors, shown beside the list.
const HELPER_NOTES: [&str; 2] = [
    "trim, replace and pad change the string they are called on and return nothing: copy the string first (`let t = s; t.trim();`).",
    "A top-level const is not visible inside a function: read it as global::NAME, or pass it as an input.",
];

/// What `coordinatorctl explain functions` reports: the profile, its
/// interpreter ABI and limits, and every helper a Function may call.
pub(crate) fn explain() -> Value {
    json!({
        "profile": PURE_PROFILE,
        "interpreterAbi": INTERPRETER_ABI,
        "limits": limits(),
        "helpers": helpers(),
        "notes": HELPER_NOTES,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        platform::build_engine(&PROFILE, None, register_pure_packages)
    }

    #[test]
    fn padded_len_is_the_length_pad_would_build() {
        assert_eq!(padded_len("x", 6, "abc"), Some(6));
        assert_eq!(padded_len("é", 4, "ñ😀"), Some(2 + 2 + 4 + 2));
        assert_eq!(padded_len("hello", 3, "abc"), None);
        assert_eq!(padded_len("", 0, "abc"), None);
        assert_eq!(padded_len("x", usize::MAX, "😀"), Some(usize::MAX));
        assert_eq!(padded_len("x", usize::MAX, "ab"), Some(usize::MAX));
    }

    #[test]
    fn replaced_len_is_the_length_replace_would_build() {
        for (string, find, with) in [
            ("a,b,c", ",", "--"),
            ("aaaa", "a", ""),
            ("abc", "", "xy"),
            ("héllo", "é", "ee"),
            ("none", "z", "long"),
        ] {
            assert_eq!(
                replaced_len(string, find, with),
                string.replace(find, with).len(),
                "{string:?} {find:?} {with:?}"
            );
        }
    }

    #[test]
    fn replaced_len_does_not_overflow_on_huge_counts() {
        let long = "a".repeat(1 << 16);
        assert!(replaced_len(&long, "a", &long) > 1 << 31);
    }

    #[test]
    fn replace_refuses_before_it_builds_a_string_over_the_budget() {
        // Every overload checks the size it would build; the message names
        // the check, which the engine's own after-the-fact size check lacks.
        let big = "a".repeat(10_000);
        for call in [
            format!(r#"let s = "{big}"; s.replace("a", "{big}")"#),
            format!(r#"let s = "{big}"; s.replace('a', "{big}")"#),
        ] {
            let error = engine().eval::<()>(&call).unwrap_err();
            assert!(
                error.to_string().contains("replace would build"),
                "{call:.40}: {error}"
            );
        }
        assert_eq!(
            engine()
                .eval::<String>(r#"let s = "a,b"; s.replace(",", "--"); s"#)
                .unwrap(),
            "a--b"
        );
    }

    #[test]
    fn pad_refuses_before_it_builds_a_string_over_the_budget() {
        // A 4-byte padding to the character limit is four times the byte
        // limit; the engine's after-the-fact check would build it first.
        let error = engine()
            .eval::<()>(r#"let s = ""; s.pad(16384, "😀"); s"#)
            .unwrap_err();
        assert!(error.to_string().contains("pad would build"), "{error}");
        let error = engine()
            .eval::<()>(r#"let s = "a"; s.pad(3, ""); s"#)
            .unwrap_err();
        assert!(error.to_string().contains("not empty"), "{error}");
    }

    #[test]
    fn script_constants_reach_a_function_only_as_global() {
        // A top-level `const` is not in scope inside a function body.
        let error = engine()
            .eval::<INT>("const N = 5; fn f() { N } f()")
            .unwrap_err();
        assert!(
            error.to_string().contains("Variable not found: N"),
            "{error}"
        );
        assert_eq!(
            engine()
                .eval::<INT>("const N = 5; fn f() { global::N } f()")
                .unwrap(),
            5
        );
    }

    #[test]
    fn the_interpreters_own_calls_are_listed_and_run() {
        for (name, script) in [
            ("type_of", r#"type_of(1)"#),
            ("Fn", r#"fn g(x) { x } Fn("g")"#),
            ("call", r#"fn g(x) { x } call(Fn("g"), 1)"#),
            ("curry", r#"fn g(x) { x } curry(Fn("g"), 1)"#),
            ("is_def_fn", r#"is_def_fn("g", 1)"#),
            ("is_def_var", r#"is_def_var("x")"#),
            ("is_shared", r#"let x = 1; is_shared(x)"#),
        ] {
            assert!(helpers().contains(name), "{name} not listed");
            assert!(
                engine().eval::<rhai::Dynamic>(script).is_ok(),
                "{name} failed"
            );
        }
    }
}
