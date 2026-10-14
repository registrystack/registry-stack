// SPDX-License-Identifier: Apache-2.0
//! Bounded Rhai kernel shared by Action plans and callbacks. The platform owns
//! execution mechanics; BReg owns inputs and plan validation.

use registry_platform_script::rhai as platform;
use rhai::{Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position, AST};
use serde_json::Value;
use std::time::Instant;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    Source,
    Entrypoint,
    Execution,
    Result,
    Ceiling,
    Resource,
    Deadline,
}

impl PlanError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Source => "action.plan.source",
            Self::Entrypoint => "action.plan.entrypoint",
            Self::Execution => "action.plan.execution",
            Self::Result => "action.plan.result",
            Self::Ceiling => "action.plan.ceiling",
            Self::Resource => "action.plan.resource",
            Self::Deadline => "action.plan.deadline",
        }
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PlanError {}

pub(crate) fn compile_entrypoint(source: &str, entrypoint: &str) -> Result<AST, PlanError> {
    compile_entrypoint_detailed(source, entrypoint).map_err(|error| match error {
        EntrypointCompileError::SourceBound | EntrypointCompileError::Parse(_) => PlanError::Source,
        EntrypointCompileError::Entrypoint => PlanError::Entrypoint,
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

pub(crate) fn engine(deadline: Option<Instant>) -> Engine {
    platform::build_engine(&SCRIPT_PROFILE, deadline, |engine| {
        engine.register_fn("join", join_strings);
    })
}

/// Function assets narrow execution limits without adding any capability.
pub(crate) fn function_engine(
    deadline: Instant,
    limits: Option<&crate::model::CompiledPlanFunctionLimits>,
) -> Engine {
    let Some(limits) = limits else {
        return engine(Some(deadline));
    };
    let profile = platform::RhaiProfile {
        limits: platform::RhaiLimits {
            operations: limits.maximum_operations.min(MAXIMUM_OPERATIONS),
            call_levels: usize::from(limits.maximum_call_depth).min(MAXIMUM_CALL_DEPTH),
            expression_depth: usize::from(limits.maximum_expression_depth)
                .min(MAXIMUM_EXPRESSION_DEPTH),
            modules: 0,
            string_bytes: (limits.maximum_string_bytes as usize).min(MAXIMUM_STRING_BYTES),
            array_items: usize::from(limits.maximum_array_items).min(MAXIMUM_ARRAY_ITEMS),
            map_entries: usize::from(limits.maximum_map_entries).min(MAXIMUM_MAP_ENTRIES),
        },
        maximum_source_bytes: (limits.maximum_source_bytes as usize).min(MAXIMUM_SOURCE_BYTES),
        ..SCRIPT_PROFILE
    };
    platform::build_engine(&profile, Some(deadline), |engine| {
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

pub(crate) fn json_to_dynamic(value: &Value, depth: usize) -> Result<Dynamic, PlanError> {
    if depth > MAXIMUM_VALUE_DEPTH {
        return Err(PlanError::Resource);
    }
    match value {
        Value::Null => Ok(Dynamic::UNIT),
        Value::Bool(value) => Ok(Dynamic::from_bool(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(Dynamic::from_int)
            .ok_or(PlanError::Result),
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
                    return Err(PlanError::Resource);
                }
                Ok((key.clone().into(), json_to_dynamic(value, depth + 1)?))
            })
            .collect::<Result<Map, _>>()
            .map(Dynamic::from),
        _ => Err(PlanError::Resource),
    }
}
