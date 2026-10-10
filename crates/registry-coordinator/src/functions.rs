// SPDX-License-Identifier: Apache-2.0
//! Pure functions under one pinned, bounded interpreter profile.

use registry_platform_script::rhai::{self as platform, RhaiBaseEngine, RhaiLimits, RhaiProfile};
use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicIteratorPackage, BasicMapPackage,
    BasicStringPackage, LogicPackage, Package,
};
use rhai::{Dynamic, Engine, AST};
use serde_json::Value;

use crate::{PocError, Result};

/// Changing this identity requires a new definition digest.
pub const INTERPRETER_ABI: &str = "coordinator/pure-rhai-1.26.1/v1;raw-arithmetic-logic-string-array-map-iterator;ops=100000;calls=32;expr=64;string=16384;array=256;map=256;source=65536;json=131072;depth=32";

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
    pub(crate) fn compile(source: &str, mappings: &[&crate::definition::Mapping]) -> Result<Self> {
        if source.len() > PROFILE.maximum_source_bytes {
            return Err(failure("coordinator.function.source-limit").at("functions.rhai", "/"));
        }
        let mut ast = None;
        for mapping in mappings {
            if mapping.arguments.len() > 16 {
                return Err(failure("coordinator.function.arity")
                    .at("functions.rhai", format!("function {}", mapping.function)));
            }
            let checked = platform::compile_entrypoint(
                &PROFILE,
                source,
                &mapping.function,
                &[mapping.arguments.len()],
            )
            .map_err(|error| {
                let (message, field) = match error {
                    platform::RhaiCompileError::SourceBound => ("function source exceeds its byte limit".to_owned(), "/".to_owned()),
                    platform::RhaiCompileError::Parse(position) => ("function source has invalid or disabled syntax".to_owned(), format!("line {} column {}", position.line().unwrap_or(0), position.position().unwrap_or(0))),
                    platform::RhaiCompileError::Entrypoint => (format!("declare one public function with {} parameter(s); function names cannot be overloaded", mapping.arguments.len()), format!("function {}", mapping.function)),
                };
                PocError::new("coordinator.function.definition", message).at("functions.rhai", field).suggest("Correct the named function or syntax position, then rerun check.")
            })?;
            ast.get_or_insert(checked);
        }
        // A workflow with no mappings still compiles its source; invalid source
        // cannot become valid merely because no current step invokes it.
        if ast.is_none() {
            let engine = platform::build_engine(&PROFILE, None, register_pure_packages);
            ast = Some(
                engine
                    .compile(source)
                    .map_err(|_| failure("coordinator.function.definition"))?,
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for function in ast
            .as_ref()
            .into_iter()
            .flat_map(|ast| ast.iter_functions())
        {
            if !names.insert(function.name.to_owned()) || names.len() > 128 {
                return Err(failure("coordinator.function.definition"));
            }
        }
        Ok(Self { ast })
    }

    pub(crate) fn evaluate(&self, name: &str, values: Vec<&Value>) -> Result<Value> {
        let arguments = values
            .into_iter()
            .map(|value| {
                check_value(value)?;
                rhai::serde::to_dynamic(value).map_err(|_| failure("coordinator.function.input"))
            })
            .collect::<Result<Vec<Dynamic>>>()?;
        let engine = platform::build_engine(&PROFILE, None, register_pure_packages);
        let ast = self
            .ast
            .as_ref()
            .ok_or_else(|| failure("coordinator.function.definition"))?;
        let value =
            platform::call_with_fresh_scope(&engine, ast, name, arguments).map_err(|error| {
                failure(match platform::classify_failure(&error) {
                    platform::RhaiFailureCategory::ResourceExhausted => {
                        "coordinator.function.resource-limit"
                    }
                    platform::RhaiFailureCategory::Other => "coordinator.function.execution",
                })
            })?;
        let value = rhai::serde::from_dynamic(&value)
            .map_err(|_| failure("coordinator.function.output"))?;
        check_value(&value)?;
        Ok(value)
    }
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
        return Err(failure("coordinator.function.value-limit"));
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(value)
        .map_err(|_| failure("coordinator.function.json"))?;
    if bytes.len() > 131_072 {
        return Err(failure("coordinator.function.value-limit"));
    }
    Ok(())
}

fn failure(code: &'static str) -> PocError {
    PocError::new(code, match code {
        "coordinator.function.resource-limit" => "the function exceeded its operation, call-depth or value-size budget",
        "coordinator.function.value-limit" => "the structured value exceeded its size or depth budget",
        "coordinator.function.execution" => "the function could not evaluate its supplied values",
        "coordinator.function.source-limit" => "functions.rhai exceeds the 65536-byte source budget",
        _ => "the pure function boundary refused the definition or value",
    }).suggest("Inspect the named mapping and reduce bounded work or correct its declared arguments; runtime values are omitted.")
}

fn register_pure_packages(engine: &mut Engine) {
    ArithmeticPackage::new().register_into_engine(engine);
    LogicPackage::new().register_into_engine(engine);
    BasicStringPackage::new().register_into_engine(engine);
    BasicArrayPackage::new().register_into_engine(engine);
    BasicMapPackage::new().register_into_engine(engine);
    BasicIteratorPackage::new().register_into_engine(engine);
}

pub(crate) fn limits() -> Value {
    serde_json::json!({"operations":PROFILE.limits.operations,"callLevels":PROFILE.limits.call_levels,
        "expressionDepth":PROFILE.limits.expression_depth,"stringBytes":PROFILE.limits.string_bytes,
        "arrayItems":PROFILE.limits.array_items,"mapEntries":PROFILE.limits.map_entries,
        "sourceBytes":PROFILE.maximum_source_bytes,"jsonBytes":131072,"jsonDepth":32,"jsonNodes":4096,
        "maximumArguments":16,"maximumFunctions":128,"modules":0})
}
