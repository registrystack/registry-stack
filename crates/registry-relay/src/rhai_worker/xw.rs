// SPDX-License-Identifier: Apache-2.0
//! Versioned, deterministic helpers for reviewed Relay Rhai adapters.
//!
//! The descriptor catalog is the source of truth for registration, the public
//! function reference, and editor metadata. Every registered callable is pure
//! and receives all variable inputs explicitly. Nothing in this module grants
//! source, credential, filesystem, clock, random, network, or logging access.

use crosswalk_functions::{date, email, ids, json as cwjson, redaction, text, FunctionError};
use rhai::{
    serde::{from_dynamic, to_dynamic},
    Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Scope,
};
use serde::Serialize;
use serde_json::Value;

use super::{rhai_error, validate_json_value, WorkerError, WorkerLimits, MAX_COLLECTION_ITEMS};

/// Stable standard-library ABI recorded by compiled Rhai source plans.
pub const XW_ABI_VERSION: &str = "xw.v1";

type RegisterFunction = fn(&mut Engine, WorkerLimits);

/// Machine-readable contract for one exact Rhai overload.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct XwFunctionDescriptor {
    pub abi_version: &'static str,
    pub namespace: &'static str,
    pub name: &'static str,
    pub signature: &'static str,
    pub accepted_types: &'static [&'static str],
    pub return_type: &'static str,
    pub null_behavior: &'static str,
    pub bounds: &'static str,
    pub failure_behavior: &'static str,
    pub example: &'static str,
    #[serde(skip)]
    register: RegisterFunction,
}

const NO_NULL: &str = "Null is not accepted for any argument.";
const OPTIONAL_NULL: &str =
    "Returns null when the requested value is absent; arguments do not accept null.";
const STRING_BOUNDS: &str =
    "Every input and returned string is bounded by worker.limits.max_string_bytes.";
const PURE_FAILURE: &str = "No helper-defined failure for values within worker bounds.";
const DATE_FAILURE: &str = "Invalid, unsupported, or out-of-range dates reject the evaluation with a value-free contract violation.";
const JSON_BOUNDS: &str = "Uses the worker's string, array, map, expression-depth, node-count, and frame-oriented data limits.";
const JSON_FAILURE: &str = "Invalid JSON, unsupported values, non-interoperable numbers, or exceeded bounds reject the evaluation with a value-free contract violation or budget failure.";

macro_rules! descriptor {
    ($namespace:literal, $name:literal, $signature:literal, $types:expr, $return_type:literal, $null:expr, $bounds:expr, $failure:expr, $example:literal, $register:ident) => {
        XwFunctionDescriptor {
            abi_version: XW_ABI_VERSION,
            namespace: $namespace,
            name: $name,
            signature: $signature,
            accepted_types: $types,
            return_type: $return_type,
            null_behavior: $null,
            bounds: $bounds,
            failure_behavior: $failure,
            example: $example,
            register: $register,
        }
    };
}

/// All and only the callable `xw.v1` overloads, in stable reference order.
pub static XW_V1_FUNCTIONS: &[XwFunctionDescriptor] = &[
    descriptor!(
        "xw.text",
        "trim",
        "xw.text.trim(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.trim(\"  Ada  \")",
        register_text_trim
    ),
    descriptor!(
        "xw.text",
        "lower_ascii",
        "xw.text.lower_ascii(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.lower_ascii(\"ABC-123\")",
        register_text_lower_ascii
    ),
    descriptor!(
        "xw.text",
        "upper_ascii",
        "xw.text.upper_ascii(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.upper_ascii(\"abc-123\")",
        register_text_upper_ascii
    ),
    descriptor!(
        "xw.text",
        "title_simple",
        "xw.text.title_simple(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.title_simple(\"ada lovelace\")",
        register_text_title_simple
    ),
    descriptor!(
        "xw.text",
        "normalize_space",
        "xw.text.normalize_space(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.normalize_space(\"  Ada   Lovelace  \")",
        register_text_normalize_space
    ),
    descriptor!(
        "xw.text",
        "remove_accents",
        "xw.text.remove_accents(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.remove_accents(\"Crème Brûlée\")",
        register_text_remove_accents
    ),
    descriptor!(
        "xw.text",
        "slug",
        "xw.text.slug(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.text.slug(\"Hello, WORLD!\")",
        register_text_slug
    ),
    descriptor!(
        "xw.date",
        "parse_date",
        "xw.date.parse_date(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.parse_date(\"2024-02-29\")",
        register_date_parse
    ),
    descriptor!(
        "xw.date",
        "parse_date",
        "xw.date.parse_date(value: string, pattern: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.parse_date(\"29/02/2024\", \"%d/%m/%Y\")",
        register_date_parse_pattern
    ),
    descriptor!(
        "xw.date",
        "format_date_or_datetime",
        "xw.date.format_date_or_datetime(value: string, pattern: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.format_date_or_datetime(\"2024-02-29\", \"%d/%m/%Y\")",
        register_date_format
    ),
    descriptor!(
        "xw.date",
        "age_on",
        "xw.date.age_on(birth_date: string, reference_date: string) -> int",
        &["string", "string"],
        "int",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.age_on(\"2000-05-27\", \"2026-05-26\")",
        register_date_age_on
    ),
    descriptor!(
        "xw.date",
        "years_between",
        "xw.date.years_between(start: string, end: string) -> int",
        &["string", "string"],
        "int",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.years_between(\"2020-01-01\", \"2024-01-01\")",
        register_date_years_between
    ),
    descriptor!(
        "xw.date",
        "days_between",
        "xw.date.days_between(start: string, end: string) -> int",
        &["string", "string"],
        "int",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.days_between(\"2024-01-01\", \"2024-01-03\")",
        register_date_days_between
    ),
    descriptor!(
        "xw.date",
        "add_days",
        "xw.date.add_days(value: string, days: int) -> string",
        &["string", "int"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.add_days(\"2024-01-01\", 2)",
        register_date_add_days
    ),
    descriptor!(
        "xw.date",
        "add_months",
        "xw.date.add_months(value: string, months: int) -> string",
        &["string", "int"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.add_months(\"2024-01-31\", 1)",
        register_date_add_months
    ),
    descriptor!(
        "xw.date",
        "start_of_month",
        "xw.date.start_of_month(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.start_of_month(\"2024-02-15\")",
        register_date_start_of_month
    ),
    descriptor!(
        "xw.date",
        "end_of_month",
        "xw.date.end_of_month(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.end_of_month(\"2024-02-15\")",
        register_date_end_of_month
    ),
    descriptor!(
        "xw.date",
        "min_date",
        "xw.date.min_date(left: string, right: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.min_date(\"2024-01-01\", \"2024-02-01\")",
        register_date_min
    ),
    descriptor!(
        "xw.date",
        "max_date",
        "xw.date.max_date(left: string, right: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        DATE_FAILURE,
        "xw.date.max_date(\"2024-01-01\", \"2024-02-01\")",
        register_date_max
    ),
    descriptor!(
        "xw.ids",
        "stable_hash_sha256",
        "xw.ids.stable_hash_sha256(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.ids.stable_hash_sha256(\"subject-123\")",
        register_ids_hash
    ),
    descriptor!(
        "xw.ids",
        "stable_hash_sha256",
        "xw.ids.stable_hash_sha256(value: string, non_secret_salt: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.ids.stable_hash_sha256(\"subject-123\", \"project-v1\")",
        register_ids_hash_salted
    ),
    descriptor!(
        "xw.ids",
        "prefixed_slug",
        "xw.ids.prefixed_slug(prefix: string, value: string) -> string",
        &["string", "string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.ids.prefixed_slug(\"person\", \"Ada Lovelace\")",
        register_ids_prefixed_slug
    ),
    descriptor!(
        "xw.ids",
        "clean_id",
        "xw.ids.clean_id(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.ids.clean_id(\"a b_c-d!\")",
        register_ids_clean
    ),
    descriptor!(
        "xw.json",
        "parse_json",
        "xw.json.parse_json(value: string) -> any",
        &["string"],
        "any JSON value",
        NO_NULL,
        JSON_BOUNDS,
        JSON_FAILURE,
        "xw.json.parse_json(\"{\\\"active\\\":true}\")",
        register_json_parse
    ),
    descriptor!(
        "xw.json",
        "stringify_json",
        "xw.json.stringify_json(value: any) -> string",
        &["any JSON value"],
        "string",
        NO_NULL,
        JSON_BOUNDS,
        JSON_FAILURE,
        "xw.json.stringify_json(#{ active: true })",
        register_json_stringify
    ),
    descriptor!(
        "xw.email",
        "normalize_email",
        "xw.email.normalize_email(value: string) -> string",
        &["string"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.email.normalize_email(\" USER@Example.ORG \")",
        register_email_normalize
    ),
    descriptor!(
        "xw.email",
        "email_domain",
        "xw.email.email_domain(value: string) -> string?",
        &["string"],
        "string or null",
        OPTIONAL_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.email.email_domain(\"user@example.org\")",
        register_email_domain
    ),
    descriptor!(
        "xw.email",
        "is_valid_email",
        "xw.email.is_valid_email(value: string) -> bool",
        &["string"],
        "bool",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.email.is_valid_email(\"user@example.org\")",
        register_email_validate
    ),
    descriptor!(
        "xw.redaction",
        "mask",
        "xw.redaction.mask(value: string, visible_last: int) -> string",
        &["string", "int"],
        "string",
        NO_NULL,
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.redaction.mask(\"123456789\", 4)",
        register_redaction_mask
    ),
    descriptor!(
        "xw.redaction",
        "redact",
        "xw.redaction.redact() -> string",
        &[],
        "string",
        "No arguments or null behavior.",
        STRING_BOUNDS,
        PURE_FAILURE,
        "xw.redaction.redact()",
        register_redaction_fixed
    ),
];

#[derive(Serialize)]
struct EditorMetadata<'a> {
    schema_version: u8,
    abi_version: &'static str,
    functions: &'a [XwFunctionDescriptor],
}

/// Render deterministic editor metadata from the registration catalog.
pub fn generated_editor_metadata() -> String {
    let mut output = serde_json::to_string_pretty(&EditorMetadata {
        schema_version: 1,
        abi_version: XW_ABI_VERSION,
        functions: XW_V1_FUNCTIONS,
    })
    .expect("static xw metadata serializes");
    output.push('\n');
    output
}

/// Render the public function reference from the registration catalog.
pub fn generated_function_reference() -> String {
    let mut output = String::from(
        "<!-- Generated from crates/registry-relay/src/rhai_worker/xw.rs. Do not edit by hand. -->\n\n# Relay Rhai `xw.v1` function reference\n\n`xw.v1` is available to every reviewed sandboxed Rhai source adapter. Helpers are deterministic and product-neutral. They have no network, filesystem, credential, environment, clock, random, or logging capability. Date calculations require every date explicitly, including the reference date for age calculations.\n\n| Signature | Accepted types | Null behavior | Bounds | Failure behavior | Example |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    for function in XW_V1_FUNCTIONS {
        use std::fmt::Write as _;
        let accepted = if function.accepted_types.is_empty() {
            "none".to_owned()
        } else {
            function.accepted_types.join(", ")
        };
        let _ = writeln!(
            output,
            "| `{}` | {} → {} | {} | {} | {} | `{}` |",
            function.signature,
            accepted,
            function.return_type,
            function.null_behavior,
            function.bounds,
            function.failure_behavior,
            function.example,
        );
    }
    output.push_str("\nThe callable table above is generated from the same catalog that registers functions in the Relay worker. `today`, one-argument `age_on`, `parse_datetime`, regex, phone, filesystem, clock, random, network, and logging helpers are not part of `xw.v1`.\n");
    output
}

#[derive(Clone, Copy)]
struct XwNs;
#[derive(Clone, Copy)]
struct XwTextNs;
#[derive(Clone, Copy)]
struct XwDateNs;
#[derive(Clone, Copy)]
struct XwIdsNs;
#[derive(Clone, Copy)]
struct XwJsonNs;
#[derive(Clone, Copy)]
struct XwEmailNs;
#[derive(Clone, Copy)]
struct XwRedactionNs;

/// Register the namespace tree and every function in the catalog.
pub(super) fn register(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_type_with_name::<XwNs>("XwNs");
    engine.register_type_with_name::<XwTextNs>("XwTextNs");
    engine.register_type_with_name::<XwDateNs>("XwDateNs");
    engine.register_type_with_name::<XwIdsNs>("XwIdsNs");
    engine.register_type_with_name::<XwJsonNs>("XwJsonNs");
    engine.register_type_with_name::<XwEmailNs>("XwEmailNs");
    engine.register_type_with_name::<XwRedactionNs>("XwRedactionNs");
    engine.register_get("text", |_: &mut XwNs| XwTextNs);
    engine.register_get("date", |_: &mut XwNs| XwDateNs);
    engine.register_get("ids", |_: &mut XwNs| XwIdsNs);
    engine.register_get("json", |_: &mut XwNs| XwJsonNs);
    engine.register_get("email", |_: &mut XwNs| XwEmailNs);
    engine.register_get("redaction", |_: &mut XwNs| XwRedactionNs);
    for function in XW_V1_FUNCTIONS {
        (function.register)(engine, limits);
    }
}

pub(super) fn push_into_scope(scope: &mut Scope<'_>) {
    scope.push_constant("xw", XwNs);
}

fn crosswalk_error(_error: FunctionError) -> Box<EvalAltResult> {
    rhai_error(WorkerError::ContractViolation)
}

fn bounded_string(value: String, limits: WorkerLimits) -> Result<String, Box<EvalAltResult>> {
    (value.len() <= limits.max_string_bytes)
        .then_some(value)
        .ok_or_else(|| rhai_error(WorkerError::BudgetExceeded))
}

fn bounded_crosswalk_string(
    value: Result<String, FunctionError>,
    limits: WorkerLimits,
) -> Result<String, Box<EvalAltResult>> {
    bounded_string(value.map_err(crosswalk_error)?, limits)
}

fn register_text_trim(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("trim", move |_: XwTextNs, value: ImmutableString| {
        bounded_string(text::trim(&value), limits)
    });
}
fn register_text_lower_ascii(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("lower_ascii", move |_: XwTextNs, value: ImmutableString| {
        bounded_string(text::lower_ascii(&value), limits)
    });
}
fn register_text_upper_ascii(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("upper_ascii", move |_: XwTextNs, value: ImmutableString| {
        bounded_string(text::upper_ascii(&value), limits)
    });
}
fn register_text_title_simple(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "title_simple",
        move |_: XwTextNs, value: ImmutableString| {
            bounded_string(text::title_simple(&value), limits)
        },
    );
}
fn register_text_normalize_space(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "normalize_space",
        move |_: XwTextNs, value: ImmutableString| {
            bounded_string(text::normalize_space(&value), limits)
        },
    );
}
fn register_text_remove_accents(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "remove_accents",
        move |_: XwTextNs, value: ImmutableString| {
            bounded_string(text::remove_accents(&value), limits)
        },
    );
}
fn register_text_slug(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("slug", move |_: XwTextNs, value: ImmutableString| {
        bounded_string(text::slug(&value), limits)
    });
}

fn register_date_parse(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("parse_date", move |_: XwDateNs, value: ImmutableString| {
        bounded_crosswalk_string(date::parse_date(&value, None), limits)
    });
}
fn register_date_parse_pattern(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "parse_date",
        move |_: XwDateNs, value: ImmutableString, pattern: ImmutableString| {
            bounded_crosswalk_string(date::parse_date(&value, Some(&pattern)), limits)
        },
    );
}
fn register_date_format(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "format_date_or_datetime",
        move |_: XwDateNs, value: ImmutableString, pattern: ImmutableString| {
            bounded_crosswalk_string(date::format_date_or_datetime(&value, &pattern), limits)
        },
    );
}
fn register_date_age_on(engine: &mut Engine, _: WorkerLimits) {
    engine.register_fn(
        "age_on",
        |_: XwDateNs, birth: ImmutableString, reference: ImmutableString| {
            date::age_on(&birth, &reference).map_err(crosswalk_error)
        },
    );
}
fn register_date_years_between(engine: &mut Engine, _: WorkerLimits) {
    engine.register_fn(
        "years_between",
        |_: XwDateNs, start: ImmutableString, end: ImmutableString| {
            date::years_between(&start, &end).map_err(crosswalk_error)
        },
    );
}
fn register_date_days_between(engine: &mut Engine, _: WorkerLimits) {
    engine.register_fn(
        "days_between",
        |_: XwDateNs, start: ImmutableString, end: ImmutableString| {
            date::days_between(&start, &end).map_err(crosswalk_error)
        },
    );
}
fn register_date_add_days(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "add_days",
        move |_: XwDateNs, value: ImmutableString, days: i64| {
            bounded_crosswalk_string(date::add_days(&value, days), limits)
        },
    );
}
fn register_date_add_months(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "add_months",
        move |_: XwDateNs, value: ImmutableString, months: i64| {
            bounded_crosswalk_string(date::add_months(&value, months), limits)
        },
    );
}
fn register_date_start_of_month(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "start_of_month",
        move |_: XwDateNs, value: ImmutableString| {
            bounded_crosswalk_string(date::start_of_month(&value), limits)
        },
    );
}
fn register_date_end_of_month(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "end_of_month",
        move |_: XwDateNs, value: ImmutableString| {
            bounded_crosswalk_string(date::end_of_month(&value), limits)
        },
    );
}
fn register_date_min(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "min_date",
        move |_: XwDateNs, left: ImmutableString, right: ImmutableString| {
            bounded_crosswalk_string(date::min_date(&left, &right), limits)
        },
    );
}
fn register_date_max(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "max_date",
        move |_: XwDateNs, left: ImmutableString, right: ImmutableString| {
            bounded_crosswalk_string(date::max_date(&left, &right), limits)
        },
    );
}

fn register_ids_hash(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "stable_hash_sha256",
        move |_: XwIdsNs, value: ImmutableString| {
            bounded_string(ids::stable_hash_sha256(&value, None), limits)
        },
    );
}
fn register_ids_hash_salted(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "stable_hash_sha256",
        move |_: XwIdsNs, value: ImmutableString, salt: ImmutableString| {
            bounded_string(ids::stable_hash_sha256(&value, Some(&salt)), limits)
        },
    );
}
fn register_ids_prefixed_slug(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "prefixed_slug",
        move |_: XwIdsNs, prefix: ImmutableString, value: ImmutableString| {
            bounded_string(ids::prefixed_slug(&prefix, &value), limits)
        },
    );
}
fn register_ids_clean(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("clean_id", move |_: XwIdsNs, value: ImmutableString| {
        bounded_string(ids::clean_id(&value), limits)
    });
}

fn register_json_parse(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "parse_json",
        move |_: XwJsonNs, text: ImmutableString| -> Result<Dynamic, Box<EvalAltResult>> {
            let value: Value = cwjson::parse_json(&text).map_err(crosswalk_error)?;
            validate_json_value(&value, &limits, true).map_err(rhai_error)?;
            to_dynamic(value).map_err(|_| rhai_error(WorkerError::ContractViolation))
        },
    );
}

fn register_json_stringify(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "stringify_json",
        move |_: XwJsonNs, value: Dynamic| -> Result<String, Box<EvalAltResult>> {
            validate_dynamic_value(&value, &limits, 0, &mut 0)?;
            let value: Value =
                from_dynamic(&value).map_err(|_| rhai_error(WorkerError::ContractViolation))?;
            validate_json_value(&value, &limits, true).map_err(rhai_error)?;
            let output = cwjson::stringify_json(&value).map_err(crosswalk_error)?;
            if output.len() > limits.max_string_bytes {
                return Err(rhai_error(WorkerError::BudgetExceeded));
            }
            Ok(output)
        },
    );
}

fn validate_dynamic_value(
    value: &Dynamic,
    limits: &WorkerLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), Box<EvalAltResult>> {
    *nodes = nodes.saturating_add(1);
    if depth > limits.max_expr_depth || *nodes > MAX_COLLECTION_ITEMS * 4 {
        return Err(rhai_error(WorkerError::BudgetExceeded));
    }
    if let Some(values) = value.read_lock::<Array>() {
        if values.len() > limits.max_array_items {
            return Err(rhai_error(WorkerError::BudgetExceeded));
        }
        for value in values.iter() {
            validate_dynamic_value(value, limits, depth + 1, nodes)?;
        }
        return Ok(());
    }
    if let Some(values) = value.read_lock::<Map>() {
        if values.len() > limits.max_map_entries {
            return Err(rhai_error(WorkerError::BudgetExceeded));
        }
        for (name, value) in values.iter() {
            if name.len() > limits.max_string_bytes {
                return Err(rhai_error(WorkerError::BudgetExceeded));
            }
            validate_dynamic_value(value, limits, depth + 1, nodes)?;
        }
        return Ok(());
    }
    if let Some(text) = value.read_lock::<ImmutableString>() {
        return (text.len() <= limits.max_string_bytes)
            .then_some(())
            .ok_or_else(|| rhai_error(WorkerError::BudgetExceeded));
    }
    let is_data = value.is_unit()
        || value.is::<bool>()
        || value.is::<rhai::INT>()
        || value.is::<rhai::FLOAT>()
        || value.is::<char>();
    is_data
        .then_some(())
        .ok_or_else(|| rhai_error(WorkerError::ContractViolation))
}

fn register_email_normalize(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "normalize_email",
        move |_: XwEmailNs, value: ImmutableString| {
            bounded_string(email::normalize_email(&value), limits)
        },
    );
}
fn register_email_domain(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "email_domain",
        move |_: XwEmailNs, value: ImmutableString| -> Result<Dynamic, Box<EvalAltResult>> {
            email::email_domain(&value).map_or(Ok(Dynamic::UNIT), |domain| {
                bounded_string(domain, limits).map(Dynamic::from)
            })
        },
    );
}
fn register_email_validate(engine: &mut Engine, _: WorkerLimits) {
    engine.register_fn("is_valid_email", |_: XwEmailNs, value: ImmutableString| {
        email::is_valid_email(&value)
    });
}

fn register_redaction_mask(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn(
        "mask",
        move |_: XwRedactionNs, value: ImmutableString, visible_last: i64| {
            bounded_string(
                redaction::mask(
                    &value,
                    usize::try_from(visible_last.max(0)).unwrap_or(usize::MAX),
                ),
                limits,
            )
        },
    );
}
fn register_redaction_fixed(engine: &mut Engine, limits: WorkerLimits) {
    engine.register_fn("redact", move |_: XwRedactionNs| {
        bounded_string(redaction::redact(), limits)
    });
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use rhai::FnPtr;

    use super::*;
    use crate::rhai_worker::{
        evaluate_in_process, hardened_engine, BlockingTransport, OutputSchema, OutputType,
        SourceCall, SourceResponse, TypedValue, WorkerOutcome, WorkerOutput, WorkerRequest,
    };

    struct NoCallTransport;

    impl BlockingTransport for NoCallTransport {
        fn exchange(&self, _call: SourceCall) -> Result<SourceResponse, WorkerError> {
            panic!("pure xw helper attempted a source call")
        }
    }

    fn engine_and_scope(limits: WorkerLimits) -> (Engine, Scope<'static>) {
        let engine = hardened_engine(
            &limits,
            Instant::now() + Duration::from_secs(10),
            None,
            false,
        );
        let mut scope = Scope::new();
        push_into_scope(&mut scope);
        (engine, scope)
    }

    fn eval(expression: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        let (engine, mut scope) = engine_and_scope(WorkerLimits::default());
        engine.eval_with_scope::<Dynamic>(&mut scope, expression)
    }

    fn eval_string(expression: &str) -> String {
        eval(expression)
            .expect("expression evaluates")
            .try_cast::<String>()
            .expect("expression returns a string")
    }

    fn eval_int(expression: &str) -> i64 {
        eval(expression)
            .expect("expression evaluates")
            .try_cast::<i64>()
            .expect("expression returns an integer")
    }

    fn eval_bool(expression: &str) -> bool {
        eval(expression)
            .expect("expression evaluates")
            .try_cast::<bool>()
            .expect("expression returns a boolean")
    }

    #[test]
    fn catalog_is_the_exact_xw_v1_callable_abi() {
        let actual = XW_V1_FUNCTIONS
            .iter()
            .map(|function| function.signature)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                "xw.text.trim(value: string) -> string",
                "xw.text.lower_ascii(value: string) -> string",
                "xw.text.upper_ascii(value: string) -> string",
                "xw.text.title_simple(value: string) -> string",
                "xw.text.normalize_space(value: string) -> string",
                "xw.text.remove_accents(value: string) -> string",
                "xw.text.slug(value: string) -> string",
                "xw.date.parse_date(value: string) -> string",
                "xw.date.parse_date(value: string, pattern: string) -> string",
                "xw.date.format_date_or_datetime(value: string, pattern: string) -> string",
                "xw.date.age_on(birth_date: string, reference_date: string) -> int",
                "xw.date.years_between(start: string, end: string) -> int",
                "xw.date.days_between(start: string, end: string) -> int",
                "xw.date.add_days(value: string, days: int) -> string",
                "xw.date.add_months(value: string, months: int) -> string",
                "xw.date.start_of_month(value: string) -> string",
                "xw.date.end_of_month(value: string) -> string",
                "xw.date.min_date(left: string, right: string) -> string",
                "xw.date.max_date(left: string, right: string) -> string",
                "xw.ids.stable_hash_sha256(value: string) -> string",
                "xw.ids.stable_hash_sha256(value: string, non_secret_salt: string) -> string",
                "xw.ids.prefixed_slug(prefix: string, value: string) -> string",
                "xw.ids.clean_id(value: string) -> string",
                "xw.json.parse_json(value: string) -> any",
                "xw.json.stringify_json(value: any) -> string",
                "xw.email.normalize_email(value: string) -> string",
                "xw.email.email_domain(value: string) -> string?",
                "xw.email.is_valid_email(value: string) -> bool",
                "xw.redaction.mask(value: string, visible_last: int) -> string",
                "xw.redaction.redact() -> string",
            ]
        );
        assert!(XW_V1_FUNCTIONS
            .iter()
            .all(|function| function.abi_version == XW_ABI_VERSION));
    }

    #[test]
    fn worker_evaluation_injects_xw_v1_without_a_host_effect() {
        let mut request = WorkerRequest::v1(
            r#"fn consult(ctx) {
                result.match(#{ normalized: xw.text.slug(ctx.input.subject) })
            }"#,
            "consult",
            WorkerLimits::default(),
        );
        request.input.insert(
            "subject".to_owned(),
            TypedValue::String {
                value: Some("Ada Lovelace".to_owned()),
            },
        );
        request.output_schema.insert(
            "normalized".to_owned(),
            OutputSchema {
                output_type: OutputType::String,
                nullable: false,
                max_bytes: Some(64),
                minimum: None,
                maximum: None,
            },
        );
        assert_eq!(
            evaluate_in_process(&request, Arc::new(NoCallTransport)),
            Ok(WorkerOutput::Success {
                outcome: WorkerOutcome::Match,
                outputs: std::collections::BTreeMap::from([(
                    "normalized".to_owned(),
                    TypedValue::String {
                        value: Some("ada-lovelace".to_owned()),
                    },
                )]),
            })
        );
    }

    #[test]
    fn invalid_helper_inputs_map_to_closed_value_free_errors() {
        let marker = "invalid-sensitive-marker-7129";
        for expression in [
            "xw.date.parse_date(ctx.input.subject)",
            "xw.json.parse_json(ctx.input.subject)",
        ] {
            let mut request = WorkerRequest::v1(
                format!("fn consult(ctx) {{ result.match(#{{ normalized: {expression} }}) }}"),
                "consult",
                WorkerLimits::default(),
            );
            request.input.insert(
                "subject".to_owned(),
                TypedValue::String {
                    value: Some(marker.to_owned()),
                },
            );
            request.output_schema.insert(
                "normalized".to_owned(),
                OutputSchema {
                    output_type: OutputType::String,
                    nullable: false,
                    max_bytes: Some(64),
                    minimum: None,
                    maximum: None,
                },
            );
            let error = evaluate_in_process(&request, Arc::new(NoCallTransport))
                .expect_err("invalid helper input must fail closed");
            assert_eq!(error, WorkerError::ContractViolation);
            assert!(!format!("{error:?}").contains(marker));
        }
    }

    #[test]
    fn every_registered_helper_executes_with_predecessor_parity() {
        for (expression, expected) in [
            (r#"xw.text.trim("  a  ")"#, "a"),
            (r#"xw.text.lower_ascii("ABC-123")"#, "abc-123"),
            (r#"xw.text.upper_ascii("abc-123")"#, "ABC-123"),
            (r#"xw.text.title_simple("ada lovelace")"#, "Ada Lovelace"),
            (
                r#"xw.text.normalize_space("  Ada   Lovelace  ")"#,
                "Ada Lovelace",
            ),
            (r#"xw.text.remove_accents("Crème Brûlée")"#, "Creme Brulee"),
            (r#"xw.text.slug("Hello, WORLD!")"#, "hello-world"),
            (r#"xw.date.parse_date("2024-02-29")"#, "2024-02-29"),
            (
                r#"xw.date.parse_date("29/02/2024", "%d/%m/%Y")"#,
                "2024-02-29",
            ),
            (
                r#"xw.date.format_date_or_datetime("2024-02-29", "%d/%m/%Y")"#,
                "29/02/2024",
            ),
            (r#"xw.date.add_days("2024-01-01", 2)"#, "2024-01-03"),
            (r#"xw.date.add_months("2024-01-31", 1)"#, "2024-02-29"),
            (r#"xw.date.start_of_month("2024-02-15")"#, "2024-02-01"),
            (r#"xw.date.end_of_month("2024-02-15")"#, "2024-02-29"),
            (
                r#"xw.date.min_date("2024-01-01", "2024-02-01")"#,
                "2024-01-01",
            ),
            (
                r#"xw.date.max_date("2024-01-01", "2024-02-01")"#,
                "2024-02-01",
            ),
            (
                r#"xw.ids.prefixed_slug("ps", "Hello World!")"#,
                "ps_hello-world",
            ),
            (r#"xw.ids.clean_id("a b_c-d!")"#, "ab_c-d"),
            (r#"xw.json.stringify_json(#{ b: 2 })"#, "{\"b\":2}"),
            (
                r#"xw.email.normalize_email(" USER@Example.ORG ")"#,
                "user@example.org",
            ),
            (
                r#"xw.email.email_domain("user@example.org")"#,
                "example.org",
            ),
            (r#"xw.redaction.mask("123456789", 4)"#, "*****6789"),
            (r#"xw.redaction.redact()"#, "[REDACTED]"),
        ] {
            assert_eq!(eval_string(expression), expected, "{expression}");
        }
        assert_eq!(
            eval_int(r#"xw.date.age_on("2000-05-27", "2026-05-26")"#),
            25
        );
        assert_eq!(
            eval_int(r#"xw.date.years_between("2020-01-01", "2024-01-01")"#),
            4
        );
        assert_eq!(
            eval_int(r#"xw.date.days_between("2024-01-01", "2024-01-03")"#),
            2
        );
        assert_eq!(eval_int(r#"xw.json.parse_json("{\"b\":2}").b"#), 2);
        assert!(eval_bool(r#"xw.email.is_valid_email("user@example.org")"#));
        assert!(!eval_bool(r#"xw.email.is_valid_email("@example.org")"#));
        assert_eq!(
            eval_string(r#"xw.ids.stable_hash_sha256("abc")"#),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_string(r#"xw.ids.stable_hash_sha256("seed", "salt")"#),
            eval_string(r#"xw.ids.stable_hash_sha256("seed", "salt")"#)
        );
        assert!(eval(r#"xw.email.email_domain("not-an-email")"#)
            .expect("invalid address has no domain")
            .is_unit());
    }

    #[test]
    fn implicit_time_and_unregistered_capabilities_are_absent() {
        for expression in [
            r#"xw.date.age_on("2000-01-01")"#,
            "xw.date.today()",
            r#"xw.date.parse_datetime("2024-01-01T00:00:00Z")"#,
            r#"xw.text.regex_replace("a", "a", "b")"#,
            r#"xw.phone.normalize("123")"#,
            "timestamp()",
            r#"env_var("HOME")"#,
            r#"open("/etc/passwd")"#,
            r#"exec("true")"#,
            "random()",
            r#"source::get("/records")"#,
        ] {
            assert!(
                eval(expression).is_err(),
                "{expression} must be unavailable"
            );
        }
    }

    #[test]
    fn json_helpers_use_relay_depth_width_string_and_data_type_bounds() {
        let mut limits = WorkerLimits {
            max_expr_depth: 8,
            max_string_bytes: 64,
            max_array_items: 2,
            max_map_entries: 2,
            ..WorkerLimits::default()
        };
        let (engine, mut scope) = engine_and_scope(limits);
        let mut encoded = "0".to_owned();
        for _ in 0..10 {
            encoded = format!("[{encoded}]");
        }
        scope.push("encoded", encoded);
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.json.parse_json(encoded)")
            .is_err());

        let mut nested = Dynamic::from(0_i64);
        for _ in 0..10 {
            let array: Array = vec![nested];
            nested = Dynamic::from(array);
        }
        let (engine, mut scope) = engine_and_scope(limits);
        scope.push_dynamic("nested", nested);
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.json.stringify_json(nested)")
            .is_err());

        let (engine, mut scope) = engine_and_scope(limits);
        scope.push_dynamic(
            "wide",
            Dynamic::from(vec![
                Dynamic::from(1_i64),
                Dynamic::from(2_i64),
                Dynamic::from(3_i64),
            ]),
        );
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.json.stringify_json(wide)")
            .is_err());

        limits.max_string_bytes = 8;
        let (engine, mut scope) = engine_and_scope(limits);
        scope.push("long_value", "123456789".to_owned());
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.json.stringify_json(long_value)")
            .is_err());
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.redaction.redact()")
            .is_err());

        let (engine, mut scope) = engine_and_scope(WorkerLimits::default());
        scope.push_dynamic("function", Dynamic::from(FnPtr::new("consult").unwrap()));
        assert!(engine
            .eval_with_scope::<Dynamic>(&mut scope, "xw.json.stringify_json(function)")
            .is_err());
    }

    #[test]
    fn generated_reference_and_editor_metadata_are_current() {
        assert_eq!(
            include_str!("../../docs/rhai-xw-v1.md"),
            generated_function_reference()
        );
        assert_eq!(
            include_str!("../../docs/rhai-xw-v1.editor.json"),
            generated_editor_metadata()
        );
    }

    #[test]
    #[ignore = "prints deterministic artifacts for maintainers"]
    fn print_generated_artifacts() {
        println!(
            "---MARKDOWN---\n{}---EDITOR-METADATA---\n{}",
            generated_function_reference(),
            generated_editor_metadata()
        );
    }
}
