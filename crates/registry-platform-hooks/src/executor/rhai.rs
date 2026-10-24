// SPDX-License-Identifier: Apache-2.0

//! The Rhai hook program engine (`rhai` feature).
//!
//! A hook program is one reviewed Rhai source with exactly one public
//! `handle(ctx)` entry point. It runs on the bare platform script engine
//! under the hook profile below: the standard engine with module loading,
//! `eval`, and output removed, closures refused, and fixed operation, depth,
//! and size limits. No product helper is registered, so every product runs
//! the same program the same way.

use std::time::Instant;

use registry_platform_script::rhai as platform;
use rhai::{Array, Dynamic, Map, AST};
use serde_json::Value;

use crate::{ErrorCategory, MAX_OUTPUT_BYTES};

/// The entry point every Rhai hook program declares.
pub const RHAI_HOOK_ENTRYPOINT: &str = "handle";
/// Operation budget for one run.
pub const RHAI_HOOK_MAX_OPERATIONS: u64 = 100_000;
/// Function call depth limit.
pub const RHAI_HOOK_MAX_CALL_DEPTH: usize = 32;
/// Expression nesting limit.
pub const RHAI_HOOK_MAX_EXPRESSION_DEPTH: usize = 64;
/// Source byte ceiling.
pub const RHAI_HOOK_MAX_SOURCE_BYTES: usize = 65_536;
/// Byte ceiling for one string value.
pub const RHAI_HOOK_MAX_STRING_BYTES: usize = 16_384;
/// Item ceiling for one array value.
pub const RHAI_HOOK_MAX_ARRAY_ITEMS: usize = 256;
/// Entry ceiling for one map value.
pub const RHAI_HOOK_MAX_MAP_ENTRIES: usize = 256;
/// Nesting ceiling for the envelope converted into the program's argument.
pub const RHAI_HOOK_MAX_VALUE_DEPTH: usize = 64;

/// The profile every Rhai hook program compiles and runs under.
pub const RHAI_HOOK_PROFILE: platform::RhaiProfile = platform::RhaiProfile {
    limits: platform::RhaiLimits {
        operations: RHAI_HOOK_MAX_OPERATIONS,
        call_levels: RHAI_HOOK_MAX_CALL_DEPTH,
        expression_depth: RHAI_HOOK_MAX_EXPRESSION_DEPTH,
        modules: 0,
        string_bytes: RHAI_HOOK_MAX_STRING_BYTES,
        array_items: RHAI_HOOK_MAX_ARRAY_ITEMS,
        map_entries: RHAI_HOOK_MAX_MAP_ENTRIES,
    },
    base: platform::RhaiBaseEngine::Standard,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: RHAI_HOOK_MAX_SOURCE_BYTES,
};

/// Compile `source` as a hook program: within the source ceiling, parseable
/// under the hook profile, and declaring exactly one public `handle(ctx)`.
///
/// Products call this when they admit a hook program, so admission and the
/// run path accept exactly the same sources.
///
/// # Errors
///
/// The platform's [`platform::RhaiCompileError`]: the source bound, a parse
/// position, or the entry-point contract.
pub fn compile_rhai_hook(source: &str) -> Result<AST, platform::RhaiCompileError> {
    platform::compile_entrypoint(&RHAI_HOOK_PROFILE, source, RHAI_HOOK_ENTRYPOINT, &[1])
}

/// Run one reviewed Rhai hook program: the envelope in as the entry point's
/// one argument, one canonical handler message out.
pub(crate) fn run_rhai_hook(
    source_bytes: &[u8],
    envelope: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, ErrorCategory> {
    let source = std::str::from_utf8(source_bytes).map_err(|_| ErrorCategory::Source)?;
    let ast = compile_rhai_hook(source).map_err(|_| ErrorCategory::Source)?;
    let document: Value = registry_platform_canonical_json::parse_json_strict(envelope)
        .map_err(|_| ErrorCategory::Source)?;
    let context = json_to_dynamic(&document, 0)?;
    if Instant::now() >= deadline {
        return Err(ErrorCategory::Deadline);
    }
    let engine = platform::build_engine(&RHAI_HOOK_PROFILE, Some(deadline), |_| {});
    let answer = platform::call_with_fresh_scope(&engine, &ast, RHAI_HOOK_ENTRYPOINT, (context,))
        .map_err(|error| {
        if Instant::now() >= deadline {
            ErrorCategory::Deadline
        } else if platform::classify_failure(&error)
            == platform::RhaiFailureCategory::ResourceExhausted
        {
            ErrorCategory::Resource
        } else {
            ErrorCategory::Execution
        }
    })?;
    encode_rhai_answer(&answer)
}

/// Convert the envelope into the program's argument. A number that is not a
/// 64-bit integer is a source refusal (the envelope is the product's, and a
/// hook program has no float); a value over the profile's bounds is a
/// resource refusal.
fn json_to_dynamic(value: &Value, depth: usize) -> Result<Dynamic, ErrorCategory> {
    if depth > RHAI_HOOK_MAX_VALUE_DEPTH {
        return Err(ErrorCategory::Resource);
    }
    match value {
        Value::Null => Ok(Dynamic::UNIT),
        Value::Bool(value) => Ok(Dynamic::from_bool(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(Dynamic::from_int)
            .ok_or(ErrorCategory::Source),
        Value::String(value) if value.len() <= RHAI_HOOK_MAX_STRING_BYTES => {
            Ok(Dynamic::from(value.clone()))
        }
        Value::Array(values) if values.len() <= RHAI_HOOK_MAX_ARRAY_ITEMS => values
            .iter()
            .map(|value| json_to_dynamic(value, depth + 1))
            .collect::<Result<Array, _>>()
            .map(Dynamic::from),
        Value::Object(values) if values.len() <= RHAI_HOOK_MAX_MAP_ENTRIES => values
            .iter()
            .map(|(key, value)| {
                if key.len() > RHAI_HOOK_MAX_STRING_BYTES {
                    return Err(ErrorCategory::Resource);
                }
                Ok((key.clone().into(), json_to_dynamic(value, depth + 1)?))
            })
            .collect::<Result<Map, _>>()
            .map(Dynamic::from),
        _ => Err(ErrorCategory::Resource),
    }
}

/// Turn the entry point's returned value into the canonical message bytes the
/// delivery worker parses.
///
/// A Rhai value is not JSON, so the bytes are built here rather than returned
/// by the script: the worker requires bytes that equal their own
/// canonicalization, and a script cannot be asked to order its own keys.
pub(super) fn encode_rhai_answer(answer: &Dynamic) -> Result<Vec<u8>, ErrorCategory> {
    if answer.is_unit() {
        // A handler that returns nothing proposes nothing; the worker reads
        // an empty answer as the `none` message.
        return Ok(Vec::new());
    }
    let value: Value = rhai::serde::from_dynamic(answer).map_err(|_| ErrorCategory::Execution)?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| ErrorCategory::Execution)?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(ErrorCategory::Resource);
    }
    Ok(bytes)
}
