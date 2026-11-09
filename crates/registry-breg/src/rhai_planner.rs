// SPDX-License-Identifier: Apache-2.0
//! Bounded Rhai kernel shared by Action plans and callbacks. The platform owns
//! execution mechanics; BReg owns inputs and plan validation.

use registry_platform_script::rhai as platform;
use rhai::{Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position, AST, INT};
use serde_json::Value;
use std::time::Instant;
use time::{Date, Duration, Month};

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
/// by `engine` below; every other setting is exactly this profile. The
/// deterministic base carries no function that reads the clock, sleeps, or
/// never returns, so the deadline, which is checked between operations,
/// bounds every evaluation.
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
    base: platform::RhaiBaseEngine::Deterministic,
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
    engine_with_date(deadline, None)
}

pub(crate) fn engine_with_date(deadline: Option<Instant>, evaluation_date: Option<Date>) -> Engine {
    platform::build_engine(&SCRIPT_PROFILE, deadline, move |engine| {
        register_action_helpers(engine, evaluation_date);
    })
}

/// Function assets narrow execution limits without adding any capability.
pub(crate) fn function_engine(
    deadline: Instant,
    limits: Option<&crate::model::CompiledPlanFunctionLimits>,
    evaluation_date: Option<Date>,
) -> Engine {
    let Some(limits) = limits else {
        return engine_with_date(Some(deadline), evaluation_date);
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
    platform::build_engine(&profile, Some(deadline), move |engine| {
        register_action_helpers(engine, evaluation_date);
    })
}

fn register_action_helpers(engine: &mut Engine, evaluation_date: Option<Date>) {
    engine
        .register_fn("join", join_strings)
        .register_fn("add_days", add_days)
        .register_fn("add_months", add_months);
    if let Some(evaluation_date) = evaluation_date {
        engine.register_fn("today", move || format_date(evaluation_date));
    }
}

fn helper_error() -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime("invalid date calculation".into(), Position::NONE).into()
}

fn parse_date(value: &str) -> Result<Date, Box<EvalAltResult>> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return Err(helper_error());
    }
    let year = value[0..4].parse::<i32>().map_err(|_| helper_error())?;
    let month = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
        .ok_or_else(helper_error)?;
    let day = value[8..10].parse::<u8>().map_err(|_| helper_error())?;
    if !(1..=9999).contains(&year) {
        return Err(helper_error());
    }
    Date::from_calendar_date(year, month, day).map_err(|_| helper_error())
}

fn format_date(value: Date) -> ImmutableString {
    value
        .format(time::macros::format_description!("[year]-[month]-[day]"))
        .expect("a Date always formats as an ISO calendar date")
        .into()
}

fn add_days(value: ImmutableString, days: INT) -> Result<ImmutableString, Box<EvalAltResult>> {
    if !(-365_000..=365_000).contains(&days) {
        return Err(helper_error());
    }
    parse_date(value.as_str())?
        .checked_add(Duration::days(days))
        .filter(|date| (1..=9999).contains(&date.year()))
        .map(format_date)
        .ok_or_else(helper_error)
}

fn add_months(value: ImmutableString, months: INT) -> Result<ImmutableString, Box<EvalAltResult>> {
    if !(-12_000..=12_000).contains(&months) {
        return Err(helper_error());
    }
    let date = parse_date(value.as_str())?;
    let month_index = i64::from(date.year())
        .checked_mul(12)
        .and_then(|index| index.checked_add(i64::from(u8::from(date.month())) - 1))
        .and_then(|index| index.checked_add(months))
        .ok_or_else(helper_error)?;
    let year = i32::try_from(month_index.div_euclid(12)).map_err(|_| helper_error())?;
    if !(1..=9999).contains(&year) {
        return Err(helper_error());
    }
    let month = u8::try_from(month_index.rem_euclid(12) + 1)
        .ok()
        .and_then(|month| Month::try_from(month).ok())
        .ok_or_else(helper_error)?;
    let day = date.day().min(time::util::days_in_month(month, year));
    Date::from_calendar_date(year, month, day)
        .map(format_date)
        .map_err(|_| helper_error())
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

#[cfg(test)]
#[path = "tests/rhai_planner_sandbox_tests.rs"]
mod rhai_planner_sandbox_tests;
