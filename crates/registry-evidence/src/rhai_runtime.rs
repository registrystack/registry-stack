//! Hardened, deterministic Rhai execution for Evidence bundle scripts.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use rhai::{
    Array, CallFnOptions, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Module, Scope, AST,
    INT,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    model::LookupResult,
    values::{Decimal, EntityReferenceSeed},
};

pub const MAXIMUM_OPERATIONS: u64 = 100_000;
pub const MAXIMUM_CALL_DEPTH: usize = 32;
pub const MAXIMUM_EXPRESSION_DEPTH: usize = 64;
pub const MAXIMUM_MODULES: usize = 0;
pub const MAXIMUM_STRING_BYTES: usize = 16_384;
pub const MAXIMUM_ARRAY_ITEMS: usize = 256;
pub const MAXIMUM_MAP_ENTRIES: usize = 256;
pub const MAXIMUM_FACT_ENTRIES: usize = 64;
pub const MAXIMUM_CONCEPT_VALUES: usize = 16;
pub const MAXIMUM_CODELIST_ENTRIES: usize = 4_096;
pub const MAXIMUM_SOURCE_INPUT_BYTES: usize = 1_048_576;
pub const MAXIMUM_RESULT_BYTES: usize = 65_536;
pub const MAXIMUM_PREPARATION_INPUT_BYTES: usize = 1_048_576;
pub const MAXIMUM_REQUEST_PARTS_BYTES: usize = 65_536;
pub const MAXIMUM_QUERY_PAIRS: usize = 64;
pub const MAXIMUM_QUERY_NAME_BYTES: usize = 64;
pub const MAXIMUM_QUERY_VALUE_BYTES: usize = 4_096;
pub const MAXIMUM_JSON_BODY_DEPTH: usize = 32;

const MAXIMUM_BUCKETS: usize = 64;
const MAXIMUM_ENTITY_REFERENCE_ITEMS: usize = 64;
const MAXIMUM_REQUIRED_CODE_BYTES: usize = 64;
/// One past the largest signed 64-bit integer, as the exclusive magnitude bound for any
/// ordinary floating-point number that crosses a runtime boundary.
const INTEGER_MAGNITUDE_LIMIT: f64 = 9_223_372_036_854_775_808.0;
/// Host-owned wrapper applied to every index operand by the startup source review.
const INDEX_GUARD_FUNCTION: &str = "__evidence_index";

/// Host-private marker for a `required` value that was absent. Scripts cannot name,
/// construct, catch, or observe it, and it carries no script-supplied text.
#[derive(Clone, Copy, Debug)]
struct RequiredUnavailable;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RhaiRuntimeError {
    #[error("Evidence script compilation failed")]
    Compilation,
    #[error("Evidence script has an invalid entry point")]
    EntryPoint,
    #[error("Evidence script invocation failed")]
    Invocation,
    #[error("Evidence required input is unavailable")]
    Unavailable,
    #[error("Evidence source response violates its protocol contract")]
    SourceProtocol,
    #[error("Evidence script input exceeds its bound")]
    InputBound,
    #[error("Evidence request preparation input is invalid")]
    AdapterInput,
    #[error("Evidence request preparation result violates the closed ABI")]
    PreparationResult,
    #[error("Evidence extraction result violates the closed ABI")]
    ExtractionResult,
    #[error("Evidence extracted facts violate their schema")]
    FactSchema,
    #[error("Evidence derivation result violates the closed ABI")]
    DerivationResult,
    #[error("Evidence derivation input violates its reviewed contract")]
    DerivationInput,
    #[error("Evidence evaluation context is invalid")]
    EvaluationContext,
    #[error("Evidence codelist is invalid")]
    Codelist,
}

/// A schema hook kept separate from bundle configuration while that layer is loaded.
pub trait FactSchemaValidator {
    fn is_valid(&self, facts: &Value) -> bool;
}

impl FactSchemaValidator for jsonschema::JSONSchema {
    fn is_valid(&self, facts: &Value) -> bool {
        jsonschema::JSONSchema::is_valid(self, facts)
    }
}

impl<F> FactSchemaValidator for F
where
    F: Fn(&Value) -> bool,
{
    fn is_valid(&self, facts: &Value) -> bool {
        self(facts)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledExtraction {
    ast: AST,
}

#[derive(Clone, Debug)]
pub struct CompiledPreparation {
    ast: AST,
}

#[derive(Clone, Debug)]
pub struct CompiledDerivation {
    ast: AST,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestPartRequirement {
    Forbidden,
    Optional,
    Required,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestPartsLimits {
    query: RequestPartRequirement,
    body: RequestPartRequirement,
    maximum_query_pairs: usize,
    maximum_query_name_bytes: usize,
    maximum_query_value_bytes: usize,
    maximum_json_depth: usize,
    maximum_collection_items: usize,
    maximum_string_bytes: usize,
    maximum_normalized_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestPartsBounds {
    pub maximum_query_pairs: usize,
    pub maximum_query_name_bytes: usize,
    pub maximum_query_value_bytes: usize,
    pub maximum_json_depth: usize,
    pub maximum_collection_items: usize,
    pub maximum_string_bytes: usize,
    pub maximum_normalized_bytes: usize,
}

impl RequestPartsLimits {
    pub fn new(
        query: RequestPartRequirement,
        body: RequestPartRequirement,
        bounds: RequestPartsBounds,
    ) -> Result<Self, RhaiRuntimeError> {
        let RequestPartsBounds {
            maximum_query_pairs,
            maximum_query_name_bytes,
            maximum_query_value_bytes,
            maximum_json_depth,
            maximum_collection_items,
            maximum_string_bytes,
            maximum_normalized_bytes,
        } = bounds;
        if maximum_query_pairs == 0
            || maximum_query_pairs > MAXIMUM_QUERY_PAIRS
            || maximum_query_name_bytes == 0
            || maximum_query_name_bytes > MAXIMUM_QUERY_NAME_BYTES
            || maximum_query_value_bytes == 0
            || maximum_query_value_bytes > MAXIMUM_QUERY_VALUE_BYTES
            || maximum_json_depth == 0
            || maximum_json_depth > MAXIMUM_JSON_BODY_DEPTH
            || maximum_collection_items == 0
            || maximum_collection_items > MAXIMUM_ARRAY_ITEMS
            || maximum_string_bytes == 0
            || maximum_string_bytes > MAXIMUM_STRING_BYTES
            || maximum_normalized_bytes == 0
            || maximum_normalized_bytes > MAXIMUM_REQUEST_PARTS_BYTES
        {
            return Err(RhaiRuntimeError::PreparationResult);
        }
        Ok(Self {
            query,
            body,
            maximum_query_pairs,
            maximum_query_name_bytes,
            maximum_query_value_bytes,
            maximum_json_depth,
            maximum_collection_items,
            maximum_string_bytes,
            maximum_normalized_bytes,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct QueryPair {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for QueryPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryPair")
            .field("name", &"[redacted]")
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct RequestParts {
    pub query: Vec<QueryPair>,
    pub body: Option<Value>,
}

impl fmt::Debug for RequestParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestParts")
            .field("query_pairs", &self.query.len())
            .field("body_present", &self.body.is_some())
            .finish()
    }
}

/// Strict proleptic-Gregorian date exposed to Rhai as an opaque typed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CalendarDate(NaiveDate);

impl CalendarDate {
    pub fn parse(input: &str) -> Result<Self, RhaiRuntimeError> {
        if !is_canonical_date_text(input) {
            return Err(RhaiRuntimeError::EvaluationContext);
        }
        NaiveDate::parse_from_str(input, "%Y-%m-%d")
            .map(Self)
            .map_err(|_| RhaiRuntimeError::EvaluationContext)
    }

    pub fn as_naive_date(self) -> NaiveDate {
        self.0
    }
}

/// Strict RFC 3339 instant normalized to UTC without ambient clock access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcInstant(DateTime<Utc>);

impl UtcInstant {
    pub fn parse(input: &str) -> Result<Self, RhaiRuntimeError> {
        if !is_strict_rfc3339(input) {
            return Err(RhaiRuntimeError::EvaluationContext);
        }
        DateTime::parse_from_rfc3339(input)
            .map(|value| Self(value.with_timezone(&Utc)))
            .map_err(|_| RhaiRuntimeError::EvaluationContext)
    }

    pub fn as_utc(self) -> DateTime<Utc> {
        self.0
    }
}

/// A validated local clock time carrying its explicit UTC offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalLocalTime(ImmutableString);

impl LegalLocalTime {
    pub fn parse(input: &str) -> Result<Self, RhaiRuntimeError> {
        if !is_strict_local_time(input) {
            return Err(RhaiRuntimeError::EvaluationContext);
        }
        Ok(Self(input.into()))
    }
}

/// Read-only, bounded mapping handle. Rhai can only pass it to `codelist_lookup`.
#[derive(Clone)]
pub struct CodelistHandle {
    entries: Arc<BTreeMap<String, String>>,
}

impl CodelistHandle {
    pub fn new(entries: BTreeMap<String, String>) -> Result<Self, RhaiRuntimeError> {
        if entries.len() > MAXIMUM_CODELIST_ENTRIES
            || entries.iter().any(|(input, output)| {
                input.is_empty()
                    || output.is_empty()
                    || input.len() > MAXIMUM_STRING_BYTES
                    || output.len() > MAXIMUM_STRING_BYTES
            })
        {
            return Err(RhaiRuntimeError::Codelist);
        }
        Ok(Self {
            entries: Arc::new(entries),
        })
    }
}

impl fmt::Debug for CodelistHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodelistHandle")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

/// The only values derivation may pass to the lead output gate.
#[derive(Clone)]
pub enum DerivedValue {
    Json(Value),
    Decimal(Decimal),
    EntityReferenceSeed(EntityReferenceSeed),
    EntityReferenceSeedList(Vec<EntityReferenceSeed>),
}

impl fmt::Debug for DerivedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(value) => formatter
                .debug_struct("DerivedValue::Json")
                .field("form", &json_form(value))
                .finish(),
            Self::Decimal(_) => formatter.write_str("DerivedValue::Decimal([REDACTED])"),
            Self::EntityReferenceSeed(_) => {
                formatter.write_str("DerivedValue::EntityReferenceSeed([REDACTED])")
            }
            Self::EntityReferenceSeedList(values) => formatter
                .debug_struct("DerivedValue::EntityReferenceSeedList")
                .field("count", &values.len())
                .finish(),
        }
    }
}

fn json_form(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[derive(Clone)]
pub struct DerivedConceptValue {
    pub concept_id: String,
    pub value: DerivedValue,
}

impl fmt::Debug for DerivedConceptValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedConceptValue")
            .field("concept_id", &self.concept_id)
            .field("value", &self.value)
            .finish()
    }
}

/// Exact deterministic input to `derive`.
#[derive(Clone, Debug)]
pub struct EvaluationContext {
    observed_at: UtcInstant,
    legal_local_date: CalendarDate,
    legal_local_time: LegalLocalTime,
    parameters: Map,
    codelists: BTreeMap<String, CodelistHandle>,
}

impl EvaluationContext {
    pub fn new(
        observed_at: UtcInstant,
        legal_local_date: CalendarDate,
        legal_local_time: LegalLocalTime,
        parameters: &Value,
        codelists: BTreeMap<String, CodelistHandle>,
    ) -> Result<Self, RhaiRuntimeError> {
        if codelists.len() > MAXIMUM_MAP_ENTRIES
            || codelists
                .keys()
                .any(|name| name.is_empty() || name.len() > MAXIMUM_STRING_BYTES)
        {
            return Err(RhaiRuntimeError::EvaluationContext);
        }
        validate_json_bound(parameters, MAXIMUM_RESULT_BYTES)
            .map_err(|_| RhaiRuntimeError::EvaluationContext)?;
        let parameters = parameters_to_map(parameters)?;
        Ok(Self {
            observed_at,
            legal_local_date,
            legal_local_time,
            parameters,
            codelists,
        })
    }

    fn into_dynamic(self) -> Dynamic {
        let mut codelists = Map::new();
        for (name, handle) in self.codelists {
            codelists.insert(name.into(), Dynamic::from(handle));
        }
        let mut context = Map::new();
        context.insert("observed_at".into(), Dynamic::from(self.observed_at));
        context.insert(
            "legal_local_date".into(),
            Dynamic::from(self.legal_local_date),
        );
        context.insert(
            "legal_local_time".into(),
            Dynamic::from(self.legal_local_time),
        );
        context.insert("parameters".into(), Dynamic::from(self.parameters));
        context.insert("codelists".into(), Dynamic::from(codelists));
        Dynamic::from(context)
    }
}

/// One immutable capability allowlist used by every bundle script.
pub struct RhaiRuntime {
    engine: Engine,
}

impl fmt::Debug for RhaiRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhaiRuntime(<hardened>)")
    }
}

impl Default for RhaiRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl RhaiRuntime {
    pub fn new() -> Self {
        let mut engine = Engine::new_raw();
        engine
            .set_max_operations(MAXIMUM_OPERATIONS)
            .set_max_call_levels(MAXIMUM_CALL_DEPTH)
            .set_max_expr_depths(MAXIMUM_EXPRESSION_DEPTH, MAXIMUM_EXPRESSION_DEPTH)
            .set_max_modules(MAXIMUM_MODULES)
            .set_max_string_size(MAXIMUM_STRING_BYTES)
            .set_max_array_size(MAXIMUM_ARRAY_ITEMS)
            .set_max_map_size(MAXIMUM_MAP_ENTRIES)
            .set_allow_anonymous_fn(false)
            .disable_symbol("import")
            .disable_symbol("export")
            .disable_symbol("eval")
            .disable_symbol("print")
            .disable_symbol("debug")
            .disable_symbol("while")
            .disable_symbol("until")
            .disable_symbol("loop")
            .disable_symbol("do")
            .disable_symbol("switch")
            .disable_symbol("try")
            .disable_symbol("catch")
            .disable_symbol("..")
            .disable_symbol("..=")
            .disable_symbol("?.")
            .disable_symbol("??");

        let mut iterators = Module::new();
        iterators.set_iterable::<Array>();
        engine.register_global_module(iterators.into());

        register_language_essentials(&mut engine);
        register_evidence_primitives(&mut engine);

        Self { engine }
    }

    pub fn compile_preparation(
        &self,
        source: &str,
    ) -> Result<CompiledPreparation, RhaiRuntimeError> {
        self.compile_exact(source, "prepare", 2)
            .map(|ast| CompiledPreparation { ast })
    }

    pub fn compile_extraction(&self, source: &str) -> Result<CompiledExtraction, RhaiRuntimeError> {
        self.compile_exact(source, "extract", 2)
            .map(|ast| CompiledExtraction { ast })
    }

    pub fn compile_derivation(&self, source: &str) -> Result<CompiledDerivation, RhaiRuntimeError> {
        self.compile_exact(source, "derive", 3)
            .map(|ast| CompiledDerivation { ast })
    }

    pub fn prepare(
        &self,
        script: &CompiledPreparation,
        selectors: &Value,
        parameters: &Value,
        limits: &RequestPartsLimits,
    ) -> Result<RequestParts, RhaiRuntimeError> {
        validate_adapter_inputs(selectors, parameters)?;
        let selectors = adapter_object_to_dynamic(selectors)?;
        let parameters = adapter_object_to_dynamic(parameters)?;
        let result = self
            .engine
            .call_fn_with_options::<Dynamic>(
                CallFnOptions::new().eval_ast(false),
                &mut Scope::new(),
                &script.ast,
                "prepare",
                (selectors, parameters),
            )
            .map_err(|error| classify_invocation_error(error, ScriptStage::Preparation))?;
        decode_request_parts(result, limits)
    }

    pub fn extract<V>(
        &self,
        script: &CompiledExtraction,
        source_response: &Value,
        parameters: &Value,
        fact_schema: &V,
    ) -> Result<LookupResult, RhaiRuntimeError>
    where
        V: FactSchemaValidator + ?Sized,
    {
        validate_json_bound(source_response, MAXIMUM_SOURCE_INPUT_BYTES)?;
        if !json_numbers_are_supported(source_response) {
            return Err(RhaiRuntimeError::InputBound);
        }
        validate_adapter_object(parameters)?;
        let input =
            rhai::serde::to_dynamic(source_response).map_err(|_| RhaiRuntimeError::InputBound)?;
        let parameters = adapter_object_to_dynamic(parameters)?;
        let result = self
            .engine
            .call_fn_with_options::<Dynamic>(
                CallFnOptions::new().eval_ast(false),
                &mut Scope::new(),
                &script.ast,
                "extract",
                (input, parameters),
            )
            .map_err(|error| classify_invocation_error(error, ScriptStage::Extraction))?;
        decode_lookup_result(result, fact_schema)
    }

    pub fn derive(
        &self,
        script: &CompiledDerivation,
        facts: &BTreeMap<String, Value>,
        selectors: &Value,
        evaluation_context: EvaluationContext,
    ) -> Result<Vec<DerivedConceptValue>, RhaiRuntimeError> {
        if facts.len() > MAXIMUM_FACT_ENTRIES {
            return Err(RhaiRuntimeError::InputBound);
        }
        let facts_value = Value::Object(
            facts
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        );
        validate_json_bound(&facts_value, MAXIMUM_RESULT_BYTES)?;
        if !json_numbers_are_supported(&facts_value) {
            return Err(RhaiRuntimeError::InputBound);
        }
        let facts =
            rhai::serde::to_dynamic(facts_value).map_err(|_| RhaiRuntimeError::InputBound)?;
        validate_adapter_object(selectors)?;
        let selectors = adapter_object_to_dynamic(selectors)?;
        let context = evaluation_context.into_dynamic();
        let result = self
            .engine
            .call_fn_with_options::<Dynamic>(
                CallFnOptions::new().eval_ast(false),
                &mut Scope::new(),
                &script.ast,
                "derive",
                (facts, selectors, context),
            )
            .map_err(|error| classify_invocation_error(error, ScriptStage::Derivation))?;
        decode_derivation_result(result)
    }

    fn compile_exact(
        &self,
        source: &str,
        function_name: &str,
        parameter_count: usize,
    ) -> Result<AST, RhaiRuntimeError> {
        if source.len() > MAXIMUM_RESULT_BYTES {
            return Err(RhaiRuntimeError::InputBound);
        }
        let guarded = guarded_script_source(source)?;
        let ast = self
            .engine
            .compile(&guarded)
            .map_err(|_| RhaiRuntimeError::Compilation)?;
        let mut names = BTreeSet::new();
        let mut entry_points = 0usize;
        for function in ast.iter_functions() {
            if !names.insert(function.name) {
                return Err(RhaiRuntimeError::EntryPoint);
            }
            if function.name == function_name {
                if function.params.len() != parameter_count
                    || function.access != rhai::FnAccess::Public
                {
                    return Err(RhaiRuntimeError::EntryPoint);
                }
                entry_points += 1;
            }
        }
        if entry_points != 1 {
            return Err(RhaiRuntimeError::EntryPoint);
        }
        Ok(ast)
    }

    #[cfg(test)]
    fn engine(&self) -> &Engine {
        &self.engine
    }
}

fn register_language_essentials(engine: &mut Engine) {
    engine
        .register_fn("==", |left: INT, right: INT| left == right)
        .register_fn("!=", |left: INT, right: INT| left != right)
        .register_fn("<", |left: INT, right: INT| left < right)
        .register_fn("<=", |left: INT, right: INT| left <= right)
        .register_fn(">", |left: INT, right: INT| left > right)
        .register_fn(">=", |left: INT, right: INT| left >= right)
        .register_fn("!", |value: bool| !value)
        .register_fn("==", |left: bool, right: bool| left == right)
        .register_fn("!=", |left: bool, right: bool| left != right)
        .register_fn("==", |left: ImmutableString, right: ImmutableString| {
            left == right
        })
        .register_fn("!=", |left: ImmutableString, right: ImmutableString| {
            left != right
        })
        .register_get("len", |array: &mut Array| {
            INT::try_from(array.len()).unwrap_or(INT::MAX)
        })
        .register_fn("len", |map: Map| {
            INT::try_from(map.len()).unwrap_or(INT::MAX)
        })
        .register_fn("contains", |map: Map, name: ImmutableString| {
            map.contains_key(name.as_str())
        })
        .register_fn("push", bounded_array_push)
        .register_fn("replace", literal_string_replace)
        .register_fn("parse_integer", parse_integer)
        .register_fn(INDEX_GUARD_FUNCTION, guard_index)
        .register_fn(INDEX_GUARD_FUNCTION, guard_index_key);
}

fn register_evidence_primitives(engine: &mut Engine) {
    engine
        .register_type_with_name::<CalendarDate>("Date")
        .register_type_with_name::<UtcInstant>("Instant")
        .register_type_with_name::<LegalLocalTime>("LegalLocalTime")
        .register_type_with_name::<Decimal>("Decimal")
        .register_type_with_name::<EntityReferenceSeed>("EntityReferenceSeed")
        .register_type_with_name::<CodelistHandle>("CodelistHandle")
        .register_fn("parse_date", parse_date)
        .register_fn("parse_instant", parse_instant)
        .register_fn("decimal", parse_decimal)
        .register_fn("parse_decimal", parse_decimal)
        .register_fn("integer_to_decimal", integer_to_decimal)
        .register_fn("add_calendar_years", add_calendar_years)
        .register_fn("add_calendar_months", add_calendar_months)
        .register_fn("compare_dates", compare_dates)
        .register_fn("compare_instants", compare_instants)
        .register_fn("days_between", days_between)
        .register_fn("compare_decimals", compare_decimals)
        .register_fn("bucket_number", bucket_number)
        .register_fn("entity_reference_seed", entity_reference_seed)
        .register_fn("codelist_lookup", codelist_lookup)
        .register_fn("list_contains", list_contains)
        .register_fn("set_contains", set_contains)
        .register_fn("required", required)
        .register_fn("is_missing", is_missing);
}

fn parse_date(input: &str) -> Result<CalendarDate, Box<EvalAltResult>> {
    CalendarDate::parse(input).map_err(|_| primitive_error("invalid_date"))
}

fn parse_instant(input: &str) -> Result<UtcInstant, Box<EvalAltResult>> {
    UtcInstant::parse(input).map_err(|_| primitive_error("invalid_instant"))
}

fn parse_decimal(input: &str) -> Result<Decimal, Box<EvalAltResult>> {
    Decimal::parse(input).map_err(|_| primitive_error("invalid_decimal"))
}

fn integer_to_decimal(value: INT) -> Decimal {
    Decimal::from_integer(value)
}

fn add_calendar_years(date: CalendarDate, years: INT) -> Result<CalendarDate, Box<EvalAltResult>> {
    if !(-1_000..=1_000).contains(&years) {
        return Err(primitive_error("calendar_years_out_of_bounds"));
    }
    let months = years
        .checked_mul(12)
        .ok_or_else(|| primitive_error("calendar_years_out_of_bounds"))?;
    add_calendar_months(date, months)
}

fn add_calendar_months(
    date: CalendarDate,
    months: INT,
) -> Result<CalendarDate, Box<EvalAltResult>> {
    if !(-12_000..=12_000).contains(&months) {
        return Err(primitive_error("calendar_months_out_of_bounds"));
    }
    let month_index = i64::from(date.0.year())
        .checked_mul(12)
        .and_then(|value| value.checked_add(i64::from(date.0.month0())))
        .and_then(|value| value.checked_add(months))
        .ok_or_else(|| primitive_error("invalid_calendar_result"))?;
    let year = i32::try_from(month_index.div_euclid(12))
        .map_err(|_| primitive_error("invalid_calendar_result"))?;
    let month = u32::try_from(month_index.rem_euclid(12) + 1)
        .map_err(|_| primitive_error("invalid_calendar_result"))?;
    let day = date.0.day().min(last_day_of_month(year, month)?);
    NaiveDate::from_ymd_opt(year, month, day)
        .map(CalendarDate)
        .ok_or_else(|| primitive_error("invalid_calendar_result"))
}

fn compare_dates(left: CalendarDate, right: CalendarDate) -> INT {
    ordering_value(left.cmp(&right))
}

fn compare_instants(left: UtcInstant, right: UtcInstant) -> INT {
    ordering_value(left.cmp(&right))
}

fn days_between(first: CalendarDate, second: CalendarDate) -> Result<INT, Box<EvalAltResult>> {
    let days = second.0.signed_duration_since(first.0).num_days();
    if !(-365_000..=365_000).contains(&days) {
        return Err(primitive_error("calendar_days_out_of_bounds"));
    }
    Ok(days)
}

fn compare_decimals(left: Decimal, right: Decimal) -> INT {
    ordering_value(left.compare(&right))
}

fn bucket_number(value: Decimal, boundaries: Array) -> Result<ImmutableString, Box<EvalAltResult>> {
    if boundaries.is_empty() || boundaries.len() > MAXIMUM_BUCKETS {
        return Err(primitive_error("invalid_numeric_buckets"));
    }

    let mut parsed = Vec::with_capacity(boundaries.len());
    let mut codes = BTreeSet::new();
    for boundary in boundaries {
        let map = boundary
            .try_cast::<Map>()
            .ok_or_else(|| primitive_error("invalid_numeric_buckets"))?;
        if !has_exact_keys(&map, &["minimumInclusive", "maximumExclusive", "code"]) {
            return Err(primitive_error("invalid_numeric_buckets"));
        }
        let minimum = map["minimumInclusive"]
            .clone()
            .try_cast::<Decimal>()
            .ok_or_else(|| primitive_error("invalid_numeric_buckets"))?;
        let maximum = map["maximumExclusive"]
            .clone()
            .try_cast::<Decimal>()
            .ok_or_else(|| primitive_error("invalid_numeric_buckets"))?;
        let code = map["code"]
            .clone()
            .try_cast::<ImmutableString>()
            .ok_or_else(|| primitive_error("invalid_numeric_buckets"))?;
        if minimum.compare(&maximum) != Ordering::Less
            || code.is_empty()
            || code.len() > MAXIMUM_STRING_BYTES
            || !codes.insert(code.to_string())
        {
            return Err(primitive_error("invalid_numeric_buckets"));
        }
        if parsed.last().is_some_and(
            |(_, previous_maximum, _): &(Decimal, Decimal, ImmutableString)| {
                previous_maximum.compare(&minimum) != Ordering::Equal
            },
        ) {
            return Err(primitive_error("invalid_numeric_buckets"));
        }
        parsed.push((minimum, maximum, code));
    }

    parsed
        .into_iter()
        .find(|(minimum, maximum, _)| {
            value.compare(minimum) != Ordering::Less && value.compare(maximum) == Ordering::Less
        })
        .map(|(_, _, code)| code)
        .ok_or_else(|| primitive_error("number_outside_bucket_range"))
}

fn entity_reference_seed(input: &str) -> Result<EntityReferenceSeed, Box<EvalAltResult>> {
    EntityReferenceSeed::new(input).map_err(|_| primitive_error("invalid_entity_reference_seed"))
}

fn codelist_lookup(handle: CodelistHandle, code: &str) -> Dynamic {
    handle
        .entries
        .get(code)
        .cloned()
        .map(Dynamic::from)
        .unwrap_or(Dynamic::UNIT)
}

fn list_contains(values: Array, needle: Dynamic) -> Result<bool, Box<EvalAltResult>> {
    let needle = scalar_value(&needle).ok_or_else(|| primitive_error("invalid_scalar"))?;
    let values = bounded_scalar_values(&values)?;
    Ok(values.contains(&needle))
}

fn set_contains(values: Array, needle: Dynamic) -> Result<bool, Box<EvalAltResult>> {
    let needle = scalar_value(&needle).ok_or_else(|| primitive_error("invalid_scalar"))?;
    let values = bounded_scalar_values(&values)?;
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(primitive_error("set_contains_duplicate"));
        }
    }
    Ok(unique.contains(&needle))
}

/// Validates the whole bounded collection before any containment answer exists, so a
/// value that violates the declared `array<scalar>` input fails even when an earlier
/// item already matches.
fn bounded_scalar_values(values: &Array) -> Result<Vec<ScalarValue>, Box<EvalAltResult>> {
    if values.len() > MAXIMUM_ARRAY_ITEMS {
        return Err(primitive_error("collection_out_of_bounds"));
    }
    values
        .iter()
        .map(|value| scalar_value(value).ok_or_else(|| primitive_error("invalid_scalar")))
        .collect()
}

fn bounded_array_push(array: &mut Array, value: Dynamic) -> Result<(), Box<EvalAltResult>> {
    if array.len() >= MAXIMUM_ARRAY_ITEMS {
        return Err(primitive_error("collection_out_of_bounds"));
    }
    array.push(value);
    Ok(())
}

fn literal_string_replace(
    value: &mut ImmutableString,
    from: &str,
    to: &str,
) -> Result<(), Box<EvalAltResult>> {
    let occurrences = if from.is_empty() {
        value.chars().count().saturating_add(1)
    } else {
        value.match_indices(from).count()
    };
    let retained = if from.is_empty() {
        value.len()
    } else {
        value
            .len()
            .checked_sub(
                occurrences
                    .checked_mul(from.len())
                    .ok_or_else(|| primitive_error("string_out_of_bounds"))?,
            )
            .ok_or_else(|| primitive_error("string_out_of_bounds"))?
    };
    let output_len = retained
        .checked_add(
            occurrences
                .checked_mul(to.len())
                .ok_or_else(|| primitive_error("string_out_of_bounds"))?,
        )
        .ok_or_else(|| primitive_error("string_out_of_bounds"))?;
    if output_len > MAXIMUM_STRING_BYTES {
        return Err(primitive_error("string_out_of_bounds"));
    }
    *value = value.replace(from, to).into();
    Ok(())
}

fn parse_integer(value: &str) -> Result<INT, Box<EvalAltResult>> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || value.starts_with('+')
    {
        return Err(primitive_error("invalid_integer"));
    }
    value
        .parse::<INT>()
        .map_err(|_| primitive_error("invalid_integer"))
}

/// Returns the value, or terminates the invocation with the host-private unavailable
/// signal.
///
/// The second argument is validated as a safe shape and then deliberately discarded.
/// Shape validation cannot prove that a code is a reviewed bundle literal rather than a
/// value derived from protected source data, so carrying it into any observable failure
/// would open a disclosure channel. Every unavailable termination therefore collapses to
/// the same value-free class in public problems, audit, and service logs.
fn required(value: Dynamic, error_code: &str) -> Result<Dynamic, Box<EvalAltResult>> {
    if !is_safe_error_code(error_code) {
        return Err(primitive_error("invalid_required_error_code"));
    }
    if value.is_unit() {
        return Err(EvalAltResult::ErrorRuntime(
            Dynamic::from(RequiredUnavailable),
            rhai::Position::NONE,
        )
        .into());
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum ScriptStage {
    Preparation,
    Extraction,
    Derivation,
}

fn classify_invocation_error(error: Box<EvalAltResult>, stage: ScriptStage) -> RhaiRuntimeError {
    if contains_unavailable_signal(&error) {
        RhaiRuntimeError::Unavailable
    } else {
        match stage {
            ScriptStage::Preparation if contains_runtime_signal(&error, "adapter_input_error") => {
                RhaiRuntimeError::AdapterInput
            }
            ScriptStage::Extraction if contains_runtime_signal(&error, "source_protocol_error") => {
                RhaiRuntimeError::SourceProtocol
            }
            ScriptStage::Derivation
                if contains_runtime_signal(&error, "derivation_input_error") =>
            {
                RhaiRuntimeError::DerivationInput
            }
            _ => RhaiRuntimeError::Invocation,
        }
    }
}

fn contains_unavailable_signal(error: &EvalAltResult) -> bool {
    match error {
        EvalAltResult::ErrorRuntime(value, _) => value.is::<RequiredUnavailable>(),
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _)
        | EvalAltResult::ErrorInModule(_, inner, _) => contains_unavailable_signal(inner),
        _ => false,
    }
}

fn contains_runtime_signal(error: &EvalAltResult, expected: &str) -> bool {
    match error {
        EvalAltResult::ErrorRuntime(value, _) => value
            .clone()
            .try_cast::<ImmutableString>()
            .is_some_and(|signal| signal.as_str() == expected),
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _)
        | EvalAltResult::ErrorInModule(_, inner, _) => contains_runtime_signal(inner, expected),
        _ => false,
    }
}

fn is_missing(value: Dynamic) -> bool {
    value.is_unit()
}

fn decode_lookup_result<V>(
    result: Dynamic,
    fact_schema: &V,
) -> Result<LookupResult, RhaiRuntimeError>
where
    V: FactSchemaValidator + ?Sized,
{
    let map = result
        .try_cast::<Map>()
        .ok_or(RhaiRuntimeError::ExtractionResult)?;
    let outcome = map
        .get("outcome")
        .and_then(|value| value.clone().try_cast::<ImmutableString>())
        .ok_or(RhaiRuntimeError::ExtractionResult)?;
    match outcome.as_str() {
        "no_match" if has_exact_keys(&map, &["outcome"]) => Ok(LookupResult::NoMatch),
        "ambiguous" if has_exact_keys(&map, &["outcome"]) => Ok(LookupResult::Ambiguous),
        "match" if has_exact_keys(&map, &["outcome", "facts"]) => {
            let facts_dynamic = map.get("facts").ok_or(RhaiRuntimeError::ExtractionResult)?;
            if !dynamic_is_json(facts_dynamic, FloatAdmission::AdapterSurface) {
                return Err(RhaiRuntimeError::ExtractionResult);
            }
            let facts: Value = rhai::serde::from_dynamic(facts_dynamic)
                .map_err(|_| RhaiRuntimeError::ExtractionResult)?;
            let object = facts
                .as_object()
                .ok_or(RhaiRuntimeError::ExtractionResult)?;
            if object.len() > MAXIMUM_FACT_ENTRIES {
                return Err(RhaiRuntimeError::ExtractionResult);
            }
            validate_json_bound(&facts, MAXIMUM_RESULT_BYTES)
                .map_err(|_| RhaiRuntimeError::ExtractionResult)?;
            if !fact_schema.is_valid(&facts) {
                return Err(RhaiRuntimeError::FactSchema);
            }
            Ok(LookupResult::Match(
                object
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            ))
        }
        _ => Err(RhaiRuntimeError::ExtractionResult),
    }
}

fn decode_derivation_result(result: Dynamic) -> Result<Vec<DerivedConceptValue>, RhaiRuntimeError> {
    let array = result
        .try_cast::<Array>()
        .ok_or(RhaiRuntimeError::DerivationResult)?;
    if array.is_empty() || array.len() > MAXIMUM_CONCEPT_VALUES {
        return Err(RhaiRuntimeError::DerivationResult);
    }
    let mut result = Vec::with_capacity(array.len());
    let mut identifiers = BTreeSet::new();
    let mut total_bytes = 2usize;
    for item in array {
        let map = item
            .try_cast::<Map>()
            .ok_or(RhaiRuntimeError::DerivationResult)?;
        if !has_exact_keys(&map, &["concept_id", "value"]) {
            return Err(RhaiRuntimeError::DerivationResult);
        }
        let concept_id = map["concept_id"]
            .clone()
            .try_cast::<ImmutableString>()
            .ok_or(RhaiRuntimeError::DerivationResult)?
            .to_string();
        if concept_id.is_empty()
            || concept_id.len() > MAXIMUM_STRING_BYTES
            || !identifiers.insert(concept_id.clone())
        {
            return Err(RhaiRuntimeError::DerivationResult);
        }
        let value = decode_derived_value(map["value"].clone())?;
        let encoded_identifier = serde_json::to_vec(&concept_id)
            .map_err(|_| RhaiRuntimeError::DerivationResult)?
            .len();
        total_bytes = total_bytes
            .checked_add(encoded_identifier)
            .and_then(|total| total.checked_add(derived_value_size(&value).ok()?))
            .and_then(|total| total.checked_add(29))
            .ok_or(RhaiRuntimeError::DerivationResult)?;
        if total_bytes > MAXIMUM_RESULT_BYTES {
            return Err(RhaiRuntimeError::DerivationResult);
        }
        result.push(DerivedConceptValue { concept_id, value });
    }
    Ok(result)
}

fn decode_derived_value(value: Dynamic) -> Result<DerivedValue, RhaiRuntimeError> {
    if value.is::<Decimal>() {
        return Ok(DerivedValue::Decimal(value.cast::<Decimal>()));
    }
    if value.is::<EntityReferenceSeed>() {
        return Ok(DerivedValue::EntityReferenceSeed(
            value.cast::<EntityReferenceSeed>(),
        ));
    }
    if value.is_array() {
        let array = value.clone_cast::<Array>();
        if array.iter().any(Dynamic::is::<EntityReferenceSeed>) {
            if array.is_empty()
                || array.len() > MAXIMUM_ENTITY_REFERENCE_ITEMS
                || !array.iter().all(Dynamic::is::<EntityReferenceSeed>)
            {
                return Err(RhaiRuntimeError::DerivationResult);
            }
            return Ok(DerivedValue::EntityReferenceSeedList(
                array
                    .into_iter()
                    .map(Dynamic::cast::<EntityReferenceSeed>)
                    .collect(),
            ));
        }
    }
    if !dynamic_is_json(&value, FloatAdmission::Rejected) {
        return Err(RhaiRuntimeError::DerivationResult);
    }
    let json = rhai::serde::from_dynamic::<Value>(&value)
        .map_err(|_| RhaiRuntimeError::DerivationResult)?;
    validate_json_bound(&json, MAXIMUM_RESULT_BYTES)
        .map_err(|_| RhaiRuntimeError::DerivationResult)?;
    Ok(DerivedValue::Json(json))
}

/// Reviews the reviewed-language surface and returns the source with every index
/// operand routed through the host-owned index guard. The raw engine remains the
/// capability boundary; this lexical review is an enforceable language contract over
/// governed bundle scripts and is not claimed as a sandbox perimeter.
fn guarded_script_source(source: &str) -> Result<String, RhaiRuntimeError> {
    validate_top_level_functions(source)?;
    let mut insertions = review_script_bytes(source)?;
    insertions.sort_by_key(|(offset, _)| *offset);
    let mut guarded = String::with_capacity(source.len());
    let mut copied = 0usize;
    for (offset, guard) in insertions {
        guarded.push_str(&source[copied..offset]);
        match guard {
            IndexGuard::Open => {
                guarded.push_str(INDEX_GUARD_FUNCTION);
                guarded.push('(');
            }
            IndexGuard::Close => guarded.push(')'),
        }
        copied = offset;
    }
    guarded.push_str(&source[copied..]);
    Ok(guarded)
}

fn validate_top_level_functions(source: &str) -> Result<(), RhaiRuntimeError> {
    let mut cursor = ScriptCursor::new(source);
    while cursor.skip_trivia()? {
        let _private = cursor.consume_word("private");
        cursor.skip_trivia()?;
        if !cursor.consume_word("fn") {
            return Err(RhaiRuntimeError::Compilation);
        }
        cursor.skip_trivia()?;
        if !cursor.consume_identifier() {
            return Err(RhaiRuntimeError::Compilation);
        }
        cursor.skip_trivia()?;
        cursor.consume_balanced(b'(', b')')?;
        cursor.skip_trivia()?;
        cursor.consume_balanced(b'{', b'}')?;
    }
    Ok(())
}

/// Walks the script the way Rhai 1.25.1 tokenizes it, rejects the forbidden constructs,
/// and reports where the index guard must wrap an index operand.
fn review_script_bytes(source: &str) -> Result<Vec<(usize, IndexGuard)>, RhaiRuntimeError> {
    let mut cursor = ScriptCursor::new(source);
    let mut insertions = Vec::new();
    let mut braces = Vec::new();
    let mut previous_significant = None;
    let mut previous_ends_value = false;
    while cursor.index < cursor.bytes.len() {
        if cursor.skip_comment()? {
            continue;
        }
        let byte = cursor.bytes[cursor.index];
        if byte.is_ascii_whitespace() {
            cursor.index += 1;
            continue;
        }
        match byte {
            b'"' | b'\'' => {
                cursor.skip_quoted()?;
                previous_significant = Some(byte);
                previous_ends_value = true;
            }
            b'`' => return Err(RhaiRuntimeError::Compilation),
            b'#' => {
                cursor.consume_map_literal_start()?;
                braces.push(BraceKind::MapLiteral);
                previous_significant = Some(b'{');
                previous_ends_value = false;
            }
            b'{' => {
                if expects_operand(previous_significant) {
                    return Err(RhaiRuntimeError::Compilation);
                }
                cursor.index += 1;
                braces.push(BraceKind::Block);
                previous_significant = Some(b'{');
                previous_ends_value = false;
            }
            b'}' => {
                let kind = braces.pop().ok_or(RhaiRuntimeError::Compilation)?;
                cursor.index += 1;
                previous_significant = Some(b'}');
                previous_ends_value = kind == BraceKind::MapLiteral;
            }
            b'[' if previous_ends_value => {
                let close = cursor.matching_bracket()?;
                cursor.index += 1;
                if cursor.negative_literal_follows()? {
                    return Err(RhaiRuntimeError::Compilation);
                }
                insertions.push((cursor.index, IndexGuard::Open));
                insertions.push((close, IndexGuard::Close));
                previous_significant = Some(b'[');
                previous_ends_value = false;
            }
            _ if is_identifier_start(byte) => {
                let word = cursor.take_identifier();
                if word == "Fn"
                    || word == INDEX_GUARD_FUNCTION
                    || matches!(word, "call" | "curry") && previous_significant == Some(b'.')
                    || word == "if" && expects_operand(previous_significant)
                {
                    return Err(RhaiRuntimeError::Compilation);
                }
                previous_significant = word.as_bytes().last().copied();
                previous_ends_value = !keyword_precedes_value(word);
            }
            _ => {
                cursor.index += 1;
                previous_significant = Some(byte);
                previous_ends_value = matches!(byte, b')' | b']') || byte.is_ascii_digit();
            }
        }
    }
    if !braces.is_empty() {
        return Err(RhaiRuntimeError::Compilation);
    }
    Ok(insertions)
}

/// Whether the previous significant byte leaves an expression waiting for an operand.
///
/// Rhai indexes a block or an `if` chain that sits in operand position, so `}` there ends
/// a value while `}` at statement position does not. A byte scanner cannot tell those two
/// closing braces apart, and a missing guard would restore negative indexing. Both forms
/// are therefore outside the reviewed language, which keeps every remaining `[` exactly
/// classifiable.
fn expects_operand(previous_significant: Option<u8>) -> bool {
    matches!(
        previous_significant,
        Some(
            b'=' | b'('
                | b','
                | b':'
                | b'['
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'<'
                | b'>'
                | b'!'
                | b'&'
                | b'|'
                | b'^'
                | b'?'
        )
    )
}

/// Reserved words after which `[` opens an array literal instead of indexing a value.
fn keyword_precedes_value(word: &str) -> bool {
    matches!(
        word,
        "as" | "break"
            | "case"
            | "catch"
            | "const"
            | "continue"
            | "do"
            | "else"
            | "export"
            | "fn"
            | "for"
            | "if"
            | "import"
            | "in"
            | "let"
            | "loop"
            | "private"
            | "return"
            | "switch"
            | "throw"
            | "try"
            | "until"
            | "while"
    )
}

#[derive(Clone, Copy)]
enum IndexGuard {
    Open,
    Close,
}

/// Whether a closing brace ends a map literal, which is a value, or a block, which is
/// not. The distinction decides whether a following `[` indexes or opens an array.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BraceKind {
    Block,
    MapLiteral,
}

/// Rejects a negative array index however it was computed, because Rhai counts a
/// negative index from the end of the array.
fn guard_index(index: INT) -> Result<INT, Box<EvalAltResult>> {
    if index < 0 {
        return Err(primitive_error("negative_index"));
    }
    Ok(index)
}

fn guard_index_key(key: ImmutableString) -> ImmutableString {
    key
}

struct ScriptCursor<'a> {
    source: &'a str,
    bytes: &'a [u8],
    index: usize,
}

impl<'a> ScriptCursor<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            index: 0,
        }
    }

    fn skip_trivia(&mut self) -> Result<bool, RhaiRuntimeError> {
        loop {
            while self
                .bytes
                .get(self.index)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.index += 1;
            }
            if !self.skip_comment()? {
                return Ok(self.index < self.bytes.len());
            }
        }
    }

    fn skip_noise(&mut self) -> Result<bool, RhaiRuntimeError> {
        if self.skip_comment()? {
            return Ok(true);
        }
        match self.bytes.get(self.index).copied() {
            Some(b'"' | b'\'') => {
                self.skip_quoted()?;
                Ok(true)
            }
            Some(b'`') => Err(RhaiRuntimeError::Compilation),
            Some(b'#') => {
                self.check_map_literal_start()?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Rhai 1.25.1 reads `#"..."#` and `##"..."##` as raw strings, whose bodies may
    /// contain quotes. Only `#{` stays inside the reviewed language, so every other `#`
    /// fails rather than letting this scanner and the Rhai tokenizer disagree about
    /// where a string ends.
    fn check_map_literal_start(&self) -> Result<(), RhaiRuntimeError> {
        if self.bytes.get(self.index + 1) != Some(&b'{') {
            return Err(RhaiRuntimeError::Compilation);
        }
        Ok(())
    }

    fn consume_map_literal_start(&mut self) -> Result<(), RhaiRuntimeError> {
        self.check_map_literal_start()?;
        self.index += 2;
        Ok(())
    }

    /// Position of the `]` that closes the bracket at the cursor.
    fn matching_bracket(&self) -> Result<usize, RhaiRuntimeError> {
        let mut cursor = ScriptCursor {
            source: self.source,
            bytes: self.bytes,
            index: self.index,
        };
        let mut depth = 0usize;
        while cursor.index < cursor.bytes.len() {
            if cursor.skip_noise()? {
                continue;
            }
            match cursor.bytes[cursor.index] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(cursor.index);
                    }
                }
                _ => {}
            }
            cursor.index += 1;
        }
        Err(RhaiRuntimeError::Compilation)
    }

    /// Whether the expression at the cursor opens with a negative numeric literal.
    fn negative_literal_follows(&self) -> Result<bool, RhaiRuntimeError> {
        let mut lookahead = ScriptCursor {
            source: self.source,
            bytes: self.bytes,
            index: self.index,
        };
        lookahead.skip_trivia()?;
        if lookahead.bytes.get(lookahead.index) != Some(&b'-') {
            return Ok(false);
        }
        lookahead.index += 1;
        lookahead.skip_trivia()?;
        Ok(lookahead
            .bytes
            .get(lookahead.index)
            .is_some_and(u8::is_ascii_digit))
    }

    fn take_identifier(&mut self) -> &'a str {
        let start = self.index;
        self.index += 1;
        while self
            .bytes
            .get(self.index)
            .is_some_and(|byte| is_identifier_continue(*byte))
        {
            self.index += 1;
        }
        &self.source[start..self.index]
    }

    fn skip_comment(&mut self) -> Result<bool, RhaiRuntimeError> {
        if self.bytes.get(self.index..self.index + 2) == Some(b"//") {
            self.index += 2;
            while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                self.index += 1;
            }
            return Ok(true);
        }
        if self.bytes.get(self.index..self.index + 2) == Some(b"/*") {
            self.index += 2;
            while self.index + 1 < self.bytes.len()
                && self.bytes.get(self.index..self.index + 2) != Some(b"*/")
            {
                self.index += 1;
            }
            if self.bytes.get(self.index..self.index + 2) != Some(b"*/") {
                return Err(RhaiRuntimeError::Compilation);
            }
            self.index += 2;
            return Ok(true);
        }
        Ok(false)
    }

    fn skip_quoted(&mut self) -> Result<(), RhaiRuntimeError> {
        let quote = self.bytes[self.index];
        self.index += 1;
        while self.index < self.bytes.len() {
            match self.bytes[self.index] {
                b'\\' => self.index = self.index.saturating_add(2),
                byte if byte == quote => {
                    self.index += 1;
                    return Ok(());
                }
                _ => self.index += 1,
            }
        }
        Err(RhaiRuntimeError::Compilation)
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        let remaining = &self.source[self.index..];
        if !remaining.starts_with(expected) {
            return false;
        }
        let end = self.index + expected.len();
        if self
            .bytes
            .get(end)
            .is_some_and(|byte| is_identifier_continue(*byte))
        {
            return false;
        }
        self.index = end;
        true
    }

    fn consume_identifier(&mut self) -> bool {
        if !self
            .bytes
            .get(self.index)
            .is_some_and(|byte| is_identifier_start(*byte))
        {
            return false;
        }
        self.index += 1;
        while self
            .bytes
            .get(self.index)
            .is_some_and(|byte| is_identifier_continue(*byte))
        {
            self.index += 1;
        }
        true
    }

    fn consume_balanced(&mut self, open: u8, close: u8) -> Result<(), RhaiRuntimeError> {
        if self.bytes.get(self.index) != Some(&open) {
            return Err(RhaiRuntimeError::Compilation);
        }
        let mut depth = 0usize;
        while self.index < self.bytes.len() {
            if self.skip_noise()? {
                continue;
            }
            match self.bytes[self.index] {
                byte if byte == open => depth += 1,
                byte if byte == close => {
                    depth -= 1;
                    self.index += 1;
                    if depth == 0 {
                        return Ok(());
                    }
                    continue;
                }
                _ => {}
            }
            self.index += 1;
        }
        Err(RhaiRuntimeError::Compilation)
    }
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

fn validate_adapter_inputs(selectors: &Value, parameters: &Value) -> Result<(), RhaiRuntimeError> {
    validate_adapter_object(selectors)?;
    validate_adapter_object(parameters)?;
    let combined = Value::Array(vec![selectors.clone(), parameters.clone()]);
    let size = serde_json::to_vec(&combined)
        .map_err(|_| RhaiRuntimeError::AdapterInput)?
        .len();
    if size > MAXIMUM_PREPARATION_INPUT_BYTES {
        return Err(RhaiRuntimeError::InputBound);
    }
    Ok(())
}

fn validate_adapter_object(value: &Value) -> Result<(), RhaiRuntimeError> {
    if !value.is_object() || !adapter_value_is_supported(value) {
        return Err(RhaiRuntimeError::AdapterInput);
    }
    Ok(())
}

fn adapter_value_is_supported(value: &Value) -> bool {
    match value {
        Value::Bool(_) => true,
        Value::Number(value) => value.as_i64().is_some(),
        Value::String(value) => value.len() <= MAXIMUM_STRING_BYTES,
        Value::Array(values) => {
            values.len() <= MAXIMUM_ARRAY_ITEMS && values.iter().all(adapter_value_is_supported)
        }
        Value::Object(values) => {
            values.len() <= MAXIMUM_MAP_ENTRIES
                && !is_typed_derivation_envelope(values)
                && values.iter().all(|(name, value)| {
                    name.len() <= MAXIMUM_STRING_BYTES && adapter_value_is_supported(value)
                })
        }
        Value::Null => false,
    }
}

fn adapter_object_to_dynamic(value: &Value) -> Result<Dynamic, RhaiRuntimeError> {
    let object = value.as_object().ok_or(RhaiRuntimeError::AdapterInput)?;
    object
        .iter()
        .map(|(name, value)| Ok((name.as_str().into(), adapter_value_to_dynamic(value)?)))
        .collect::<Result<Map, RhaiRuntimeError>>()
        .map(Dynamic::from)
}

fn adapter_value_to_dynamic(value: &Value) -> Result<Dynamic, RhaiRuntimeError> {
    match value {
        Value::Bool(value) => Ok(Dynamic::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(Dynamic::from)
            .ok_or(RhaiRuntimeError::AdapterInput),
        Value::String(value) if value.len() <= MAXIMUM_STRING_BYTES => {
            Ok(Dynamic::from(value.clone()))
        }
        Value::Array(values) if values.len() <= MAXIMUM_ARRAY_ITEMS => values
            .iter()
            .map(adapter_value_to_dynamic)
            .collect::<Result<Array, _>>()
            .map(Dynamic::from),
        Value::Object(values)
            if values.len() <= MAXIMUM_MAP_ENTRIES && !is_typed_derivation_envelope(values) =>
        {
            values
                .iter()
                .map(|(name, value)| {
                    if name.len() > MAXIMUM_STRING_BYTES {
                        return Err(RhaiRuntimeError::AdapterInput);
                    }
                    Ok((name.as_str().into(), adapter_value_to_dynamic(value)?))
                })
                .collect::<Result<Map, _>>()
                .map(Dynamic::from)
        }
        _ => Err(RhaiRuntimeError::AdapterInput),
    }
}

fn is_typed_derivation_envelope(values: &serde_json::Map<String, Value>) -> bool {
    values.len() == 2
        && values.get("type") == Some(&Value::String("decimal".to_string()))
        && values.get("value").is_some_and(Value::is_string)
}

fn decode_request_parts(
    result: Dynamic,
    limits: &RequestPartsLimits,
) -> Result<RequestParts, RhaiRuntimeError> {
    let map = result
        .try_cast::<Map>()
        .ok_or(RhaiRuntimeError::PreparationResult)?;
    if !has_exact_keys(&map, &["query", "body"]) {
        return Err(RhaiRuntimeError::PreparationResult);
    }

    let query = map["query"]
        .clone()
        .try_cast::<Array>()
        .ok_or(RhaiRuntimeError::PreparationResult)?;
    if query.len() > limits.maximum_query_pairs || query.len() > MAXIMUM_QUERY_PAIRS {
        return Err(RhaiRuntimeError::PreparationResult);
    }
    let query = query
        .into_iter()
        .map(|pair| {
            let pair = pair
                .try_cast::<Map>()
                .ok_or(RhaiRuntimeError::PreparationResult)?;
            if !has_exact_keys(&pair, &["name", "value"]) {
                return Err(RhaiRuntimeError::PreparationResult);
            }
            let name = pair["name"]
                .clone()
                .try_cast::<ImmutableString>()
                .ok_or(RhaiRuntimeError::PreparationResult)?
                .to_string();
            let value = pair["value"]
                .clone()
                .try_cast::<ImmutableString>()
                .ok_or(RhaiRuntimeError::PreparationResult)?
                .to_string();
            if name.is_empty()
                || name.len() > limits.maximum_query_name_bytes
                || name.len() > MAXIMUM_QUERY_NAME_BYTES
                || name.len() > limits.maximum_string_bytes
                || value.len() > limits.maximum_query_value_bytes
                || value.len() > MAXIMUM_QUERY_VALUE_BYTES
                || value.len() > limits.maximum_string_bytes
                || name.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
                || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                return Err(RhaiRuntimeError::PreparationResult);
            }
            Ok(QueryPair { name, value })
        })
        .collect::<Result<Vec<_>, RhaiRuntimeError>>()?;

    validate_part_requirement(limits.query, !query.is_empty())?;
    let body = if map["body"].is_unit() {
        None
    } else {
        if !dynamic_is_json(&map["body"], FloatAdmission::AdapterSurface) {
            return Err(RhaiRuntimeError::PreparationResult);
        }
        let body = rhai::serde::from_dynamic::<Value>(&map["body"])
            .map_err(|_| RhaiRuntimeError::PreparationResult)?;
        if !json_numbers_are_supported(&body)
            || !json_value_within_limits(
                &body,
                limits.maximum_json_depth,
                limits.maximum_collection_items,
                limits.maximum_string_bytes,
            )
        {
            return Err(RhaiRuntimeError::PreparationResult);
        }
        Some(body)
    };
    validate_part_requirement(limits.body, body.is_some())?;

    let normalized = Value::Object(serde_json::Map::from_iter([
        ("body".to_string(), body.clone().unwrap_or(Value::Null)),
        (
            "query".to_string(),
            Value::Array(
                query
                    .iter()
                    .map(|pair| {
                        Value::Object(serde_json::Map::from_iter([
                            ("name".to_string(), Value::String(pair.name.clone())),
                            ("value".to_string(), Value::String(pair.value.clone())),
                        ]))
                    })
                    .collect(),
            ),
        ),
    ]));
    let normalized_size = serde_json::to_vec(&normalized)
        .map_err(|_| RhaiRuntimeError::PreparationResult)?
        .len();
    if normalized_size > limits.maximum_normalized_bytes
        || normalized_size > MAXIMUM_REQUEST_PARTS_BYTES
    {
        return Err(RhaiRuntimeError::PreparationResult);
    }
    Ok(RequestParts { query, body })
}

fn validate_part_requirement(
    requirement: RequestPartRequirement,
    present: bool,
) -> Result<(), RhaiRuntimeError> {
    match (requirement, present) {
        (RequestPartRequirement::Forbidden, true) | (RequestPartRequirement::Required, false) => {
            Err(RhaiRuntimeError::PreparationResult)
        }
        _ => Ok(()),
    }
}

fn json_value_within_limits(
    value: &Value,
    maximum_depth: usize,
    maximum_collection_items: usize,
    maximum_string_bytes: usize,
) -> bool {
    fn visit(
        value: &Value,
        container_depth: usize,
        maximum_depth: usize,
        maximum_collection_items: usize,
        maximum_string_bytes: usize,
    ) -> bool {
        match value {
            Value::String(value) => value.len() <= maximum_string_bytes,
            Value::Array(values) => {
                container_depth < maximum_depth
                    && values.len() <= maximum_collection_items
                    && values.iter().all(|value| {
                        visit(
                            value,
                            container_depth + 1,
                            maximum_depth,
                            maximum_collection_items,
                            maximum_string_bytes,
                        )
                    })
            }
            Value::Object(values) => {
                container_depth < maximum_depth
                    && values.len() <= maximum_collection_items
                    && values.iter().all(|(name, value)| {
                        name.len() <= maximum_string_bytes
                            && visit(
                                value,
                                container_depth + 1,
                                maximum_depth,
                                maximum_collection_items,
                                maximum_string_bytes,
                            )
                    })
            }
            _ => true,
        }
    }
    visit(
        value,
        0,
        maximum_depth,
        maximum_collection_items,
        maximum_string_bytes,
    )
}

/// Numeric admission for JSON decoded into Rhai. An integer token outside the signed
/// 64-bit range fails here instead of reaching a script as a precision-losing float; a
/// provider identifier beyond that range must be represented as a string.
fn json_numbers_are_supported(value: &Value) -> bool {
    match value {
        Value::Number(value) => value.is_i64() || value.as_f64().is_some_and(is_supported_float),
        Value::Array(values) => values.iter().all(json_numbers_are_supported),
        Value::Object(values) => values.values().all(json_numbers_are_supported),
        _ => true,
    }
}

/// An ordinary float is carried only when it is finite and its magnitude stays inside the
/// signed 64-bit integer range, which keeps every admitted number distinguishable from a
/// silently truncated large integer token.
fn is_supported_float(value: f64) -> bool {
    value.is_finite() && value.abs() < INTEGER_MAGNITUDE_LIMIT
}

/// Whether ordinary Rhai floats may appear in a decoded value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FloatAdmission {
    /// Request preparation and source extraction carry provider-shaped JSON, which may
    /// contain finite ordinary floats.
    AdapterSurface,
    /// Public derived values use the declared integer or exact Decimal forms only.
    Rejected,
}

fn dynamic_is_json(value: &Dynamic, floats: FloatAdmission) -> bool {
    if value.is_unit() || value.is_bool() || value.is_int() || value.is_string() {
        return true;
    }
    if value.is_float() {
        return floats == FloatAdmission::AdapterSurface
            && value.as_float().is_ok_and(is_supported_float);
    }
    if value.is_array() {
        return value
            .clone_cast::<Array>()
            .iter()
            .all(|value| dynamic_is_json(value, floats));
    }
    if value.is_map() {
        return value
            .clone_cast::<Map>()
            .values()
            .all(|value| dynamic_is_json(value, floats));
    }
    false
}

fn derived_value_size(value: &DerivedValue) -> Result<usize, RhaiRuntimeError> {
    match value {
        DerivedValue::Json(value) => serde_json::to_vec(value)
            .map(|bytes| bytes.len())
            .map_err(|_| RhaiRuntimeError::DerivationResult),
        DerivedValue::Decimal(value) => Ok(value.canonical().len()),
        DerivedValue::EntityReferenceSeed(value) => Ok(value.expose_for_projection().len()),
        DerivedValue::EntityReferenceSeedList(values) => {
            values.iter().try_fold(0usize, |sum, value| {
                sum.checked_add(value.expose_for_projection().len())
                    .ok_or(RhaiRuntimeError::DerivationResult)
            })
        }
    }
}

fn parameters_to_map(parameters: &Value) -> Result<Map, RhaiRuntimeError> {
    let object = parameters
        .as_object()
        .ok_or(RhaiRuntimeError::EvaluationContext)?;
    if object.len() > MAXIMUM_MAP_ENTRIES {
        return Err(RhaiRuntimeError::EvaluationContext);
    }
    object
        .iter()
        .map(|(name, value)| {
            if name.is_empty() || name.len() > MAXIMUM_STRING_BYTES {
                return Err(RhaiRuntimeError::EvaluationContext);
            }
            Ok((name.as_str().into(), parameter_to_dynamic(value)?))
        })
        .collect()
}

fn parameter_to_dynamic(value: &Value) -> Result<Dynamic, RhaiRuntimeError> {
    match value {
        Value::Bool(value) => Ok(Dynamic::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(Dynamic::from)
            .ok_or(RhaiRuntimeError::EvaluationContext),
        Value::String(value) if value.len() <= MAXIMUM_STRING_BYTES => {
            Ok(Dynamic::from(value.clone()))
        }
        Value::Array(values) if values.len() <= MAXIMUM_ARRAY_ITEMS => values
            .iter()
            .map(parameter_to_dynamic)
            .collect::<Result<Array, _>>()
            .map(Dynamic::from),
        Value::Object(object)
            if object.len() == 2
                && object.get("type") == Some(&Value::String("decimal".to_string()))
                && object.get("value").is_some_and(Value::is_string) =>
        {
            let text = object["value"]
                .as_str()
                .ok_or(RhaiRuntimeError::EvaluationContext)?;
            Decimal::parse(text)
                .map(Dynamic::from)
                .map_err(|_| RhaiRuntimeError::EvaluationContext)
        }
        Value::Object(object) if object.len() <= MAXIMUM_MAP_ENTRIES => object
            .iter()
            .map(|(name, value)| {
                if name.is_empty() || name.len() > MAXIMUM_STRING_BYTES {
                    return Err(RhaiRuntimeError::EvaluationContext);
                }
                Ok((name.as_str().into(), parameter_to_dynamic(value)?))
            })
            .collect::<Result<Map, _>>()
            .map(Dynamic::from),
        _ => Err(RhaiRuntimeError::EvaluationContext),
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ScalarValue {
    Boolean(bool),
    Integer(INT),
    String(String),
    Date(CalendarDate),
    Instant(UtcInstant),
    Decimal(String),
}

impl fmt::Debug for ScalarValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = match self {
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::String(_) => "string",
            Self::Date(_) => "date",
            Self::Instant(_) => "instant",
            Self::Decimal(_) => "decimal",
        };
        formatter
            .debug_struct("ScalarValue")
            .field("form", &form)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

fn scalar_value(value: &Dynamic) -> Option<ScalarValue> {
    if value.is_bool() {
        return Some(ScalarValue::Boolean(value.as_bool().ok()?));
    }
    if value.is_int() {
        return Some(ScalarValue::Integer(value.as_int().ok()?));
    }
    if value.is_string() {
        return Some(ScalarValue::String(
            value.clone_cast::<ImmutableString>().to_string(),
        ));
    }
    if value.is::<CalendarDate>() {
        return Some(ScalarValue::Date(value.clone_cast::<CalendarDate>()));
    }
    if value.is::<UtcInstant>() {
        return Some(ScalarValue::Instant(value.clone_cast::<UtcInstant>()));
    }
    if value.is::<Decimal>() {
        return Some(ScalarValue::Decimal(
            value.clone_cast::<Decimal>().canonical().to_string(),
        ));
    }
    None
}

fn validate_json_bound(
    value: &Value,
    maximum_serialized_bytes: usize,
) -> Result<(), RhaiRuntimeError> {
    let serialized = serde_json::to_vec(value).map_err(|_| RhaiRuntimeError::InputBound)?;
    if serialized.len() > maximum_serialized_bytes || !json_collections_are_bounded(value) {
        return Err(RhaiRuntimeError::InputBound);
    }
    Ok(())
}

fn json_collections_are_bounded(value: &Value) -> bool {
    match value {
        Value::String(value) => value.len() <= MAXIMUM_STRING_BYTES,
        Value::Array(values) => {
            values.len() <= MAXIMUM_ARRAY_ITEMS && values.iter().all(json_collections_are_bounded)
        }
        Value::Object(values) => {
            values.len() <= MAXIMUM_MAP_ENTRIES
                && values.iter().all(|(name, value)| {
                    name.len() <= MAXIMUM_STRING_BYTES && json_collections_are_bounded(value)
                })
        }
        _ => true,
    }
}

fn has_exact_keys(map: &Map, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

fn ordering_value(ordering: Ordering) -> INT {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn last_day_of_month(year: i32, month: u32) -> Result<u32, Box<EvalAltResult>> {
    let (next_year, next_month) = if month == 12 {
        (year.checked_add(1), 1)
    } else {
        (Some(year), month + 1)
    };
    let next_year = next_year.ok_or_else(|| primitive_error("invalid_calendar_result"))?;
    let first_next = NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .ok_or_else(|| primitive_error("invalid_calendar_result"))?;
    Ok((first_next - Duration::days(1)).day())
}

fn is_canonical_date_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn is_strict_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !value.is_ascii()
        || bytes.get(10) != Some(&b'T')
        || !is_canonical_date_text(&value[..10])
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let hour = parse_two_digits(&bytes[11..13]);
    let minute = parse_two_digits(&bytes[14..16]);
    let second = parse_two_digits(&bytes[17..19]);
    if !matches!(hour, Some(0..=23))
        || !matches!(minute, Some(0..=59))
        || !matches!(second, Some(0..=59))
    {
        return false;
    }
    has_strict_fraction_and_offset(&value[19..])
}

fn is_strict_local_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 9
        || !value.is_ascii()
        || bytes.get(2) != Some(&b':')
        || bytes.get(5) != Some(&b':')
    {
        return false;
    }
    let hour = parse_two_digits(&bytes[0..2]);
    let minute = parse_two_digits(&bytes[3..5]);
    let second = parse_two_digits(&bytes[6..8]);
    matches!(hour, Some(0..=23))
        && matches!(minute, Some(0..=59))
        && matches!(second, Some(0..=59))
        && has_strict_fraction_and_offset(&value[8..])
}

fn has_strict_fraction_and_offset(suffix: &str) -> bool {
    let (fraction, offset) = if let Some(rest) = suffix.strip_prefix('.') {
        let digit_count = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digit_count == 0 || digit_count > 9 {
            return false;
        }
        (&rest[..digit_count], &rest[digit_count..])
    } else {
        ("", suffix)
    };
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if offset == "Z" {
        return true;
    }
    let bytes = offset.as_bytes();
    if bytes.len() != 6 || !matches!(bytes[0], b'+' | b'-') || bytes[3] != b':' {
        return false;
    }
    matches!(parse_two_digits(&bytes[1..3]), Some(0..=23))
        && matches!(parse_two_digits(&bytes[4..6]), Some(0..=59))
}

fn parse_two_digits(value: &[u8]) -> Option<u8> {
    if value.len() != 2 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((value[0] - b'0') * 10 + value[1] - b'0')
}

fn is_safe_error_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAXIMUM_REQUIRED_CODE_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn primitive_error(code: &str) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(code.into(), rhai::Position::NONE).into()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ADULT_EXTRACTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/adult-status/adapters/source-a.rhai"
    ));
    const ADULT_DERIVATION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/adult-status/derivations/adult-status.rhai"
    ));
    const RESIDENCE_EXTRACTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/residence-region/adapters/source-b.rhai"
    ));
    const RESIDENCE_DERIVATION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/residence-region/derivations/residence-region.rhai"
    ));
    const LICENCE_EXTRACTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/professional-licence/adapters/source-c.rhai"
    ));
    const LICENCE_DERIVATION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/professional-licence/derivations/professional-licence.rhai"
    ));
    const RELATIONSHIP_EXTRACTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/legal-parent-relationship/adapters/source-d.rhai"
    ));
    const RELATIONSHIP_DERIVATION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/evidence/fixtures/acceptance/legal-parent-relationship/derivations/legal-parent-relationship.rhai"
    ));

    fn runtime() -> RhaiRuntime {
        RhaiRuntime::new()
    }

    fn context(
        parameters: Value,
        codelists: BTreeMap<String, CodelistHandle>,
    ) -> EvaluationContext {
        EvaluationContext::new(
            UtcInstant::parse("2026-08-02T00:00:00Z").expect("instant"),
            CalendarDate::parse("2026-08-02").expect("date"),
            LegalLocalTime::parse("07:00:00+07:00").expect("time"),
            &parameters,
            codelists,
        )
        .expect("context")
    }

    fn request_limits(
        query: RequestPartRequirement,
        body: RequestPartRequirement,
    ) -> RequestPartsLimits {
        RequestPartsLimits::new(
            query,
            body,
            RequestPartsBounds {
                maximum_query_pairs: MAXIMUM_QUERY_PAIRS,
                maximum_query_name_bytes: MAXIMUM_QUERY_NAME_BYTES,
                maximum_query_value_bytes: MAXIMUM_QUERY_VALUE_BYTES,
                maximum_json_depth: MAXIMUM_JSON_BODY_DEPTH,
                maximum_collection_items: MAXIMUM_ARRAY_ITEMS,
                maximum_string_bytes: MAXIMUM_STRING_BYTES,
                maximum_normalized_bytes: MAXIMUM_REQUEST_PARTS_BYTES,
            },
        )
        .expect("request limits")
    }

    #[test]
    fn engine_has_exact_normative_limits_and_disabled_module_syntax() {
        let runtime = runtime();
        let engine = runtime.engine();
        assert_eq!(engine.max_operations(), MAXIMUM_OPERATIONS);
        assert_eq!(engine.max_call_levels(), MAXIMUM_CALL_DEPTH);
        assert_eq!(engine.max_expr_depth(), MAXIMUM_EXPRESSION_DEPTH);
        assert_eq!(engine.max_function_expr_depth(), MAXIMUM_EXPRESSION_DEPTH);
        assert_eq!(engine.max_modules(), MAXIMUM_MODULES);
        assert_eq!(engine.max_string_size(), MAXIMUM_STRING_BYTES);
        assert_eq!(engine.max_array_size(), MAXIMUM_ARRAY_ITEMS);
        assert_eq!(engine.max_map_size(), MAXIMUM_MAP_ENTRIES);
        assert!(engine.is_symbol_disabled("import"));
        assert!(engine.is_symbol_disabled("export"));
        assert!(engine.is_symbol_disabled("eval"));
        assert!(engine.is_symbol_disabled("print"));
        assert!(engine.is_symbol_disabled("debug"));
        for symbol in [
            "while", "until", "loop", "do", "switch", "try", "catch", "..", "..=", "?.", "??",
        ] {
            assert!(engine.is_symbol_disabled(symbol), "{symbol}");
        }
        assert!(!engine.allow_anonymous_fn());
    }

    #[test]
    fn preparation_runs_named_helpers_with_fresh_isolated_inputs() {
        let runtime = runtime();
        let script = runtime
            .compile_preparation(
                r#"
                    fn query_pair(name, value) { #{ name: name, value: value } }
                    fn prepare(selectors, parameters) {
                        let query = [];
                        query.push(query_pair("filter", selectors.subject.values.reference));
                        query.push(query_pair("filter", parameters.status));
                        let provider_name = parameters.provider_name;
                        provider_name.replace("_", "-");
                        selectors.subject.values.reference = "mutated-only-locally";
                        #{
                            query: query,
                            body: #{
                                provider: provider_name,
                                limit: parse_integer(parameters.limit)
                            }
                        }
                    }
                "#,
            )
            .expect("preparation compiles");
        let selectors = json!({
            "subject": {"profile": "reference-v1", "values": {"reference": "person-1"}}
        });
        let parameters = json!({"status": "ACTIVE", "provider_name": "source_a", "limit": "02"});
        let limits = request_limits(
            RequestPartRequirement::Required,
            RequestPartRequirement::Required,
        );
        for _ in 0..2 {
            assert_eq!(
                runtime
                    .prepare(&script, &selectors, &parameters, &limits)
                    .expect("prepares"),
                RequestParts {
                    query: vec![
                        QueryPair {
                            name: "filter".to_string(),
                            value: "person-1".to_string(),
                        },
                        QueryPair {
                            name: "filter".to_string(),
                            value: "ACTIVE".to_string(),
                        },
                    ],
                    body: Some(json!({"limit": 2, "provider": "source-a"})),
                }
            );
        }
        assert_eq!(selectors["subject"]["values"]["reference"], "person-1");
        assert_eq!(parameters["provider_name"], "source_a");
    }

    #[test]
    fn preparation_inputs_and_request_parts_are_closed_and_bounded() {
        let runtime = runtime();
        let passthrough = runtime
            .compile_preparation(
                "fn prepare(selectors, parameters) { #{ query: parameters.query, body: () } }",
            )
            .expect("compiles");
        let limits = request_limits(
            RequestPartRequirement::Optional,
            RequestPartRequirement::Optional,
        );

        for invalid in [
            json!({"value": null}),
            json!({"value": 1.25}),
            json!({"value": {"type": "decimal", "value": "1.25"}}),
        ] {
            assert_eq!(
                runtime.prepare(&passthrough, &json!({}), &invalid, &limits),
                Err(RhaiRuntimeError::AdapterInput)
            );
        }

        for parameters in [
            json!({"query": [{"name": "", "value": "x"}]}),
            json!({"query": [{"name": "x\r", "value": "y"}]}),
            json!({"query": [{"name": "x", "value": "y\n"}]}),
            json!({"query": [{"name": "x", "value": 1}]}),
        ] {
            assert!(matches!(
                runtime.prepare(&passthrough, &json!({}), &parameters, &limits),
                Err(RhaiRuntimeError::AdapterInput | RhaiRuntimeError::PreparationResult)
            ));
        }

        let unknown = runtime
            .compile_preparation(
                "fn prepare(selectors, parameters) { #{ query: [], body: (), extra: true } }",
            )
            .expect("compiles");
        assert_eq!(
            runtime.prepare(&unknown, &json!({}), &json!({}), &limits),
            Err(RhaiRuntimeError::PreparationResult)
        );
        for body in ["parse_date(\"2026-08-02\")", "'x'"] {
            let source =
                format!("fn prepare(selectors, parameters) {{ #{{ query: [], body: {body} }} }}");
            let script = runtime.compile_preparation(&source).expect("compiles");
            assert_eq!(
                runtime.prepare(&script, &json!({}), &json!({}), &limits),
                Err(RhaiRuntimeError::PreparationResult)
            );
        }
        let forbidden_query = request_limits(
            RequestPartRequirement::Forbidden,
            RequestPartRequirement::Optional,
        );
        let query = runtime
            .compile_preparation(
                "fn prepare(selectors, parameters) { #{ query: [#{name: \"x\", value: \"y\"}], body: () } }",
            )
            .expect("compiles");
        assert_eq!(
            runtime.prepare(&query, &json!({}), &json!({}), &forbidden_query),
            Err(RhaiRuntimeError::PreparationResult)
        );

        let strict = RequestPartsLimits::new(
            RequestPartRequirement::Optional,
            RequestPartRequirement::Optional,
            RequestPartsBounds {
                maximum_query_pairs: 1,
                maximum_query_name_bytes: 1,
                maximum_query_value_bytes: 1,
                maximum_json_depth: 1,
                maximum_collection_items: 1,
                maximum_string_bytes: 1,
                maximum_normalized_bytes: 32,
            },
        )
        .expect("strict limits");
        assert_eq!(
            runtime.prepare(&query, &json!({}), &json!({}), &strict),
            Err(RhaiRuntimeError::PreparationResult)
        );
    }

    #[test]
    fn compiler_rejects_every_forbidden_candidate_construct() {
        let runtime = runtime();
        let bodies = [
            "while true {}",
            "until true {}",
            "loop {}",
            "do {} while false",
            "switch 1 { 1 => true, _ => false }",
            "try { throw \"x\"; } catch (error) {}",
            "let pointer = Fn(\"helper\");",
            "let closure = |value| value;",
            "let closure = || 1;",
            "let text = `value=${selectors}`;",
            "let value = [1, 2, 3][0..1];",
            "let value = [1, 2, 3][-1];",
            "let value = parameters?.value;",
            "let value = parameters.value ?? 0;",
            "let pointer = parameters.pointer; pointer.call();",
            "let pointer = parameters.pointer; pointer.curry(1);",
        ];
        for body in bodies {
            let source = format!(
                "fn prepare(selectors, parameters) {{ {body} #{{ query: [], body: () }} }}"
            );
            assert!(
                runtime.compile_preparation(&source).is_err(),
                "construct compiled: {body}"
            );
        }
    }

    #[test]
    fn compiler_allows_unique_helpers_but_rejects_entry_overloads() {
        let runtime = runtime();
        assert!(runtime
            .compile_preparation(
                "fn helper(value) { value } fn prepare(selectors, parameters) { #{query: [], body: helper(())} }"
            )
            .is_ok());
        for source in [
            "fn prepare(a, b) { #{query: [], body: ()} } fn prepare(a) { a }",
            "fn helper(a) { a } fn helper(a, b) { b } fn prepare(a, b) { #{query: [], body: ()} }",
            "private fn prepare(a, b) { #{query: [], body: ()} }",
        ] {
            assert_eq!(
                runtime.compile_preparation(source).unwrap_err(),
                RhaiRuntimeError::EntryPoint
            );
        }
    }

    #[test]
    fn strict_integer_parser_and_mutating_helpers_enforce_bounds() {
        for (input, expected) in [("0", 0), ("-0", 0), ("0012", 12), ("-42", -42)] {
            assert_eq!(parse_integer(input).expect("integer"), expected);
        }
        for invalid in [
            "",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "1e2",
            "١",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(parse_integer(invalid).is_err(), "{invalid}");
        }
        let mut full = vec![Dynamic::UNIT; MAXIMUM_ARRAY_ITEMS];
        assert!(bounded_array_push(&mut full, Dynamic::UNIT).is_err());
        let mut value: ImmutableString = "a".repeat(MAXIMUM_STRING_BYTES).into();
        assert!(literal_string_replace(&mut value, "", "x").is_err());
    }

    #[test]
    fn compile_requires_one_exact_entry_point_and_rejects_top_level_statements() {
        let runtime = runtime();
        assert_eq!(
            runtime
                .compile_extraction("fn derive(x) { x }")
                .unwrap_err(),
            RhaiRuntimeError::EntryPoint
        );
        assert!(runtime
            .compile_extraction("fn extract(x, parameters) { x } fn helper() {}")
            .is_ok());

        assert_eq!(
            runtime
                .compile_extraction(
                    r#"
                    throw("top_level_must_not_run");
                    fn extract(source_response, parameters) { #{ outcome: "no_match" } }
                "#,
                )
                .unwrap_err(),
            RhaiRuntimeError::Compilation
        );
    }

    #[test]
    fn ambient_and_diagnostic_capabilities_are_unavailable() {
        let runtime = runtime();
        for forbidden in [
            "print(\"x\")",
            "debug(\"x\")",
            "eval(\"40 + 2\")",
            "get_env(\"HOME\")",
            "timestamp()",
        ] {
            let source = format!(
                "fn extract(source_response, parameters) {{ {forbidden}; #{{ outcome: \"no_match\" }} }}"
            );
            if let Ok(script) = runtime.compile_extraction(&source) {
                assert_eq!(
                    runtime.extract(&script, &json!({}), &json!({}), &|_: &Value| true),
                    Err(RhaiRuntimeError::Invocation),
                    "{forbidden} must be unavailable"
                );
            }
        }
        assert!(matches!(
            runtime.compile_extraction(
                "import \"outside\" as outside; fn extract(x, parameters) { #{ outcome: \"no_match\" } }"
            ),
            Err(RhaiRuntimeError::Compilation)
        ));
    }

    #[test]
    fn extraction_decodes_only_the_closed_union_and_validates_facts() {
        let runtime = runtime();
        let valid = runtime
            .compile_extraction(
                r#"
                    fn extract(source_response, parameters) {
                        #{ outcome: "match", facts: #{ code: source_response.code } }
                    }
                "#,
            )
            .expect("compiles");
        let schema = jsonschema::JSONSchema::compile(&json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["code"],
            "properties": {"code": {"type": "string"}}
        }))
        .expect("schema");
        assert_eq!(
            runtime.extract(&valid, &json!({"code": "A"}), &json!({}), &schema),
            Ok(LookupResult::Match(BTreeMap::from([(
                "code".to_string(),
                json!("A")
            )])))
        );
        assert_eq!(
            runtime.extract(&valid, &json!({"code": 1}), &json!({}), &schema),
            Err(RhaiRuntimeError::FactSchema)
        );

        for body in [
            "#{ outcome: \"no_match\", facts: #{} }",
            "#{ outcome: \"ambiguous\", count: 2 }",
            "#{ outcome: \"match\", facts: #{}, candidates: [] }",
            "#{ outcome: \"unknown\" }",
        ] {
            let source = format!("fn extract(source_response, parameters) {{ {body} }}");
            let script = runtime.compile_extraction(&source).expect("compiles");
            assert_eq!(
                runtime.extract(&script, &json!({}), &json!({}), &|_: &Value| true),
                Err(RhaiRuntimeError::ExtractionResult)
            );
        }
    }

    #[test]
    fn extraction_source_input_uses_the_configured_one_mebibyte_boundary() {
        fn sized_json_array(serialized_bytes: usize, items: usize) -> Value {
            let payload_bytes = serialized_bytes
                .checked_sub(1 + 3 * items)
                .expect("serialized target fits array framing");
            let base = payload_bytes / items;
            let remainder = payload_bytes % items;
            let values = (0..items)
                .map(|index| Value::String("x".repeat(base + usize::from(index < remainder))))
                .collect::<Vec<_>>();
            let value = Value::Array(values);
            assert_eq!(
                serde_json::to_vec(&value).expect("serializes").len(),
                serialized_bytes
            );
            value
        }

        let runtime = runtime();
        let script = runtime
            .compile_extraction(
                "fn extract(source_response, parameters) { #{ outcome: \"no_match\" } }",
            )
            .expect("compiles");
        for size in [MAXIMUM_RESULT_BYTES + 1, MAXIMUM_SOURCE_INPUT_BYTES] {
            assert_eq!(
                runtime.extract(
                    &script,
                    &sized_json_array(size, 64),
                    &json!({}),
                    &|_: &Value| true,
                ),
                Ok(LookupResult::NoMatch),
                "source input of {size} bytes remains valid"
            );
        }
        assert_eq!(
            runtime.extract(
                &script,
                &sized_json_array(MAXIMUM_SOURCE_INPUT_BYTES + 1, 64),
                &json!({}),
                &|_: &Value| true,
            ),
            Err(RhaiRuntimeError::InputBound)
        );
    }

    #[test]
    fn dates_instants_and_calendar_arithmetic_are_strict_and_bounded() {
        assert!(CalendarDate::parse("2024-02-29").is_ok());
        for invalid in ["2023-02-29", "2026-8-02", "+2026-08-02", "2026-08-02Z"] {
            assert!(CalendarDate::parse(invalid).is_err(), "{invalid}");
        }
        assert!(UtcInstant::parse("2026-08-02T07:00:00+07:00").is_ok());
        for invalid in [
            "2026-08-02 00:00:00Z",
            "2026-08-02T00:00:60Z",
            "2026-08-02T00:00:00",
            "2026-08-02T00:00:00.1234567890Z",
        ] {
            assert!(UtcInstant::parse(invalid).is_err(), "{invalid}");
        }

        let leap = CalendarDate::parse("2008-02-29").expect("date");
        assert_eq!(
            add_calendar_years(leap, 18).expect("adds").as_naive_date(),
            NaiveDate::from_ymd_opt(2026, 2, 28).expect("date")
        );
        let month_end = CalendarDate::parse("2025-01-31").expect("date");
        assert_eq!(
            add_calendar_months(month_end, 1)
                .expect("adds")
                .as_naive_date(),
            NaiveDate::from_ymd_opt(2025, 2, 28).expect("date")
        );
        assert!(add_calendar_years(leap, 1_001).is_err());
        assert!(days_between(
            CalendarDate::parse("0001-01-01").expect("date"),
            CalendarDate::parse("2001-01-01").expect("date")
        )
        .is_err());
    }

    #[test]
    fn candidate_numeric_string_and_opaque_type_surface_is_pinned() {
        let runtime = runtime();
        let script = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        let text = "source_adapter";
                        text.replace("_", "-");
                        [#{
                            concept_id: "surface",
                            value: [
                                1.5 + 2.0 == 3.5, 1 + 2.5 == 3.5, 2.5 + 1 == 3.5,
                                5.0 % 2.0 == 1.0, 2.0 ** 3.0 == 8.0,
                                1.5 < 2.0, 1 < 2.0, 2.0 >= 1,
                                "ab" + "cd", "abc" - "b", text,
                                type_of(1.5), type_of(1),
                                type_of(parse_date("2026-08-02")),
                                type_of(parse_instant("2026-08-02T00:00:00Z")),
                                type_of(evaluation_context.legal_local_time),
                                type_of(decimal("1.25")),
                                type_of(entity_reference_seed("reference")),
                                type_of(evaluation_context.codelists["codes"])
                            ]
                        }]
                    }
                "#,
            )
            .expect("compiles");
        let codelist = CodelistHandle::new(BTreeMap::from([("A".to_string(), "B".to_string())]))
            .expect("codelist");
        let values = runtime
            .derive(
                &script,
                &BTreeMap::new(),
                &json!({}),
                context(
                    json!({}),
                    BTreeMap::from([("codes".to_string(), codelist.clone())]),
                ),
            )
            .expect("derives");
        assert!(matches!(
            &values[0].value,
            DerivedValue::Json(value)
                if value == &json!([
                    true, true, true, true, true,
                    true, true, true,
                    "abcd", "ac", "source-adapter",
                    "f64", "i64",
                    "Date", "Instant", "LegalLocalTime", "Decimal",
                    "EntityReferenceSeed", "CodelistHandle"
                ])
        ));

        // The float arithmetic surface still exists inside a script, but an ordinary
        // float result is not a public derived value.
        let float_output = runtime
            .compile_derivation(
                "fn derive(facts, selectors, evaluation_context) { [#{ concept_id: \"surface\", value: 1.5 + 2.0 }] }",
            )
            .expect("compiles");
        assert!(matches!(
            runtime.derive(
                &float_output,
                &BTreeMap::new(),
                &json!({}),
                context(json!({}), BTreeMap::from([("codes".to_string(), codelist)]))
            ),
            Err(RhaiRuntimeError::DerivationResult)
        ));
    }

    #[test]
    fn operation_exhaustion_terminates_a_hostile_script_with_a_value_free_error() {
        let runtime = runtime();
        // Unbounded loop syntax is disabled, so exhaustion is driven by
        // nesting bounded iteration over the largest admissible fact array:
        // 256 * 256 iterations exceeds the 100,000-operation ceiling.
        let script = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        let total = 0;
                        for outer in facts.items {
                            for inner in facts.items {
                                total += 1;
                            }
                        }
                        [#{ concept_id: "count", value: total }]
                    }
                "#,
            )
            .expect("compiles");
        // A small input proves the script itself is well-formed, so the
        // failure below is the operation ceiling and nothing else.
        let small = BTreeMap::from([("items".to_string(), json!([1, 2, 3, 4]))]);
        let values = runtime
            .derive(
                &script,
                &small,
                &json!({}),
                context(json!({}), BTreeMap::new()),
            )
            .expect("the bounded variant derives");
        assert!(matches!(&values[0].value, DerivedValue::Json(value) if value == &json!(16)));

        let items = (0..256).collect::<Vec<i64>>();
        let facts = BTreeMap::from([("items".to_string(), json!(items))]);
        let error = runtime
            .derive(
                &script,
                &facts,
                &json!({}),
                context(json!({}), BTreeMap::new()),
            )
            .expect_err("operation exhaustion terminates the invocation");
        assert!(matches!(error, RhaiRuntimeError::Invocation));
        let diagnostic = format!("{error} {error:?}");
        assert!(!diagnostic.contains("operations"));
        assert!(!diagnostic.contains("256"));
    }

    #[test]
    fn exact_decimals_and_validated_contiguous_buckets_work() {
        let runtime = runtime();
        let script = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        let exact = decimal("1.25");
                        let integer = integer_to_decimal(1);
                        [
                            #{ concept_id: "decimal", value: exact },
                            #{ concept_id: "comparison", value: compare_decimals(exact, integer) },
                            #{
                                concept_id: "bucket",
                                value: bucket_number(exact, evaluation_context.parameters.buckets)
                            }
                        ]
                    }
                "#,
            )
            .expect("compiles");
        let parameters = json!({
            "buckets": [
                {
                    "minimumInclusive": {"type": "decimal", "value": "0"},
                    "maximumExclusive": {"type": "decimal", "value": "1"},
                    "code": "low"
                },
                {
                    "minimumInclusive": {"type": "decimal", "value": "1"},
                    "maximumExclusive": {"type": "decimal", "value": "2"},
                    "code": "high"
                }
            ]
        });
        let values = runtime
            .derive(
                &script,
                &BTreeMap::new(),
                &json!({}),
                context(parameters, BTreeMap::new()),
            )
            .expect("derives");
        assert!(matches!(
            &values[0].value,
            DerivedValue::Decimal(value) if value.canonical() == "1.25"
        ));
        assert!(matches!(&values[1].value, DerivedValue::Json(value) if value == &json!(1)));
        assert!(matches!(&values[2].value, DerivedValue::Json(value) if value == &json!("high")));

        let invalid = vec![boundary("0", "1", "a"), boundary("2", "3", "b")];
        assert!(bucket_number(Decimal::parse("1").expect("decimal"), invalid).is_err());
    }

    #[test]
    fn derived_value_debug_redacts_every_value_carrier() {
        let seed =
            EntityReferenceSeed::new("entity-reference-debug-canary").expect("seed is valid");
        let values = [
            DerivedConceptValue {
                concept_id: "urn:example:concept:string".to_owned(),
                value: DerivedValue::Json(json!("json-debug-canary")),
            },
            DerivedConceptValue {
                concept_id: "urn:example:concept:decimal".to_owned(),
                value: DerivedValue::Decimal(Decimal::parse("8192.125").expect("decimal")),
            },
            DerivedConceptValue {
                concept_id: "urn:example:concept:reference".to_owned(),
                value: DerivedValue::EntityReferenceSeed(seed.clone()),
            },
            DerivedConceptValue {
                concept_id: "urn:example:concept:references".to_owned(),
                value: DerivedValue::EntityReferenceSeedList(vec![seed]),
            },
        ];
        let diagnostic = format!("{values:?}");
        for canary in [
            "json-debug-canary",
            "8192.125",
            "entity-reference-debug-canary",
        ] {
            assert!(!diagnostic.contains(canary), "protected value leaked");
        }
        assert!(diagnostic.contains("urn:example:concept:string"));
        assert!(diagnostic.contains("form: \"string\""));
        assert!(diagnostic.contains("count: 1"));

        let scalars = [
            ScalarValue::String("scalar-debug-canary".to_owned()),
            ScalarValue::Integer(8_192_125),
            ScalarValue::Decimal("8192.125".to_owned()),
        ];
        let diagnostic = format!("{scalars:?}");
        for canary in ["scalar-debug-canary", "8192125", "8192.125"] {
            assert!(!diagnostic.contains(canary), "protected value leaked");
        }
    }

    #[test]
    fn request_parts_debug_redacts_query_and_body_values() {
        let parts = RequestParts {
            query: vec![QueryPair {
                name: "query-name-debug-canary".to_owned(),
                value: "query-value-debug-canary".to_owned(),
            }],
            body: Some(serde_json::json!({
                "body-name-debug-canary": "body-value-debug-canary"
            })),
        };

        let diagnostic = format!("{parts:?}");
        for protected in [
            "query-name-debug-canary",
            "query-value-debug-canary",
            "body-name-debug-canary",
            "body-value-debug-canary",
        ] {
            assert!(
                !diagnostic.contains(protected),
                "request parts debug leaked protected material"
            );
        }
        assert!(diagnostic.contains("query_pairs: 1"));
        assert!(diagnostic.contains("body_present: true"));
    }

    #[test]
    fn codelist_required_missing_and_exact_collections_work() {
        let runtime = runtime();
        let script = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        let mapped = codelist_lookup(evaluation_context.codelists["regions"], facts.code);
                        [
                            #{ concept_id: "mapped", value: required(mapped, "unknown_code") },
                            #{ concept_id: "missing", value: is_missing(facts.absent) },
                            #{ concept_id: "list", value: list_contains([1, "1", true], "1") },
                            #{ concept_id: "set", value: set_contains(["A", "B"], "B") }
                        ]
                    }
                "#,
            )
            .expect("compiles");
        let handle =
            CodelistHandle::new(BTreeMap::from([("R-101".to_string(), "NORTH".to_string())]))
                .expect("codelist");
        let values = runtime
            .derive(
                &script,
                &BTreeMap::from([("code".to_string(), json!("R-101"))]),
                &json!({}),
                context(json!({}), BTreeMap::from([("regions".to_string(), handle)])),
            )
            .expect("derives");
        assert!(matches!(&values[0].value, DerivedValue::Json(value) if value == &json!("NORTH")));
        assert!(matches!(&values[1].value, DerivedValue::Json(value) if value == &json!(true)));
        assert!(matches!(&values[2].value, DerivedValue::Json(value) if value == &json!(true)));
        assert!(matches!(&values[3].value, DerivedValue::Json(value) if value == &json!(true)));
        assert!(set_contains(
            vec![Dynamic::from("A"), Dynamic::from("A")],
            Dynamic::from("A")
        )
        .is_err());
        assert!(required(Dynamic::UNIT, "protected value").is_err());
        assert!(!is_missing(Dynamic::from(false)));
    }

    #[test]
    fn derivation_decode_is_closed_and_retains_protected_types() {
        let runtime = runtime();
        let protected = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        [
                            #{ concept_id: "one", value: entity_reference_seed(facts.seed) },
                            #{
                                concept_id: "many",
                                value: [entity_reference_seed("a"), entity_reference_seed("b")]
                            }
                        ]
                    }
                "#,
            )
            .expect("compiles");
        let values = runtime
            .derive(
                &protected,
                &BTreeMap::from([("seed".to_string(), json!("protected-canary"))]),
                &json!({}),
                context(json!({}), BTreeMap::new()),
            )
            .expect("derives");
        assert!(matches!(
            values[0].value,
            DerivedValue::EntityReferenceSeed(_)
        ));
        assert!(matches!(
            &values[1].value,
            DerivedValue::EntityReferenceSeedList(values) if values.len() == 2
        ));
        assert!(!format!("{:?}", values).contains("protected-canary"));

        for result in [
            "[#{ concept_id: \"x\", value: true, extra: false }]",
            "[#{ concept_id: \"x\", value: true }, #{ concept_id: \"x\", value: false }]",
            "#{ concept_id: \"x\", value: true }",
        ] {
            let source = format!("fn derive(facts, selectors, evaluation_context) {{ {result} }}");
            let script = runtime.compile_derivation(&source).expect("compiles");
            assert!(matches!(
                runtime.derive(
                    &script,
                    &BTreeMap::new(),
                    &json!({}),
                    context(json!({}), BTreeMap::new())
                ),
                Err(RhaiRuntimeError::DerivationResult)
            ));
        }
    }

    #[test]
    fn operation_limit_and_fresh_scope_fail_closed() {
        let runtime = runtime();
        let runaway = runtime
            .compile_derivation("fn derive(facts, selectors, evaluation_context) { while true {} }")
            .unwrap_err();
        assert_eq!(runaway, RhaiRuntimeError::Compilation);

        let local_only = runtime
            .compile_derivation(
                r#"
                    fn derive(facts, selectors, evaluation_context) {
                        let invocation_local = 1;
                        [#{ concept_id: "value", value: invocation_local }]
                    }
                "#,
            )
            .expect("compiles");
        for _ in 0..2 {
            assert!(runtime
                .derive(
                    &local_only,
                    &BTreeMap::new(),
                    &json!({}),
                    context(json!({}), BTreeMap::new())
                )
                .is_ok());
        }
    }

    #[test]
    fn required_primitive_reports_closed_unavailability() {
        let runtime = runtime();
        let script = runtime
            .compile_derivation(
                r#"fn derive(facts, selectors, evaluation_context) {
                    [#{ concept_id: "urn:example:concept", value: required(facts.absent, "required_fact_missing") }]
                }"#,
            )
            .expect("script compiles");
        assert!(matches!(
            runtime.derive(
                &script,
                &BTreeMap::new(),
                &json!({}),
                context(json!({}), BTreeMap::new())
            ),
            Err(RhaiRuntimeError::Unavailable)
        ));

        let forged = runtime
            .compile_derivation(
                r#"fn derive(facts, selectors, evaluation_context) {
                    throw "registry_evidence_required_unavailable";
                }"#,
            )
            .expect("script compiles");
        assert!(matches!(
            runtime.derive(
                &forged,
                &BTreeMap::new(),
                &json!({}),
                context(json!({}), BTreeMap::new())
            ),
            Err(RhaiRuntimeError::Invocation)
        ));
        assert!(runtime
            .compile_derivation(
                r#"fn derive(facts, selectors, evaluation_context) {
                    try { required(facts.absent, "missing"); } catch (error) {}
                    [#{concept_id: "x", value: true}]
                }"#,
            )
            .is_err());
    }

    #[test]
    fn all_four_acceptance_script_pairs_run_through_one_runtime() {
        let runtime = runtime();

        let adult_facts = matched_facts(
            &runtime,
            ADULT_EXTRACTION,
            json!({"total": 1, "date_of_birth": "2008-08-02"}),
        );
        let adult = runtime
            .derive(
                &runtime
                    .compile_derivation(&candidate_derivation(ADULT_DERIVATION))
                    .expect("adult derivation compiles"),
                &adult_facts,
                &json!({}),
                context(json!({"minimum_age_years": 18}), BTreeMap::new()),
            )
            .expect("adult derives");
        assert!(matches!(&adult[0].value, DerivedValue::Json(value) if value == &json!(true)));

        let residence_facts = matched_facts(
            &runtime,
            RESIDENCE_EXTRACTION,
            json!({"total": 1, "official_residence_code": "R-101"}),
        );
        let region_map = CodelistHandle::new(BTreeMap::from([
            ("R-101".to_string(), "REGION-NORTH".to_string()),
            ("R-201".to_string(), "REGION-SOUTH".to_string()),
        ]))
        .expect("codelist");
        let residence = runtime
            .derive(
                &runtime
                    .compile_derivation(&candidate_derivation(RESIDENCE_DERIVATION))
                    .expect("residence derivation compiles"),
                &residence_facts,
                &json!({}),
                context(
                    json!({}),
                    BTreeMap::from([("region-map".to_string(), region_map)]),
                ),
            )
            .expect("residence derives");
        assert!(
            matches!(&residence[0].value, DerivedValue::Json(value) if value == &json!("REGION-NORTH"))
        );

        let licence_facts = matched_facts(
            &runtime,
            LICENCE_EXTRACTION,
            json!({
                "total": 1,
                "records": [{
                    "licence_state": "CURRENT",
                    "valid_from": "2025-01-01",
                    "valid_until": "2026-08-20",
                    "historical_states": ["PENDING"]
                }]
            }),
        );
        let licence = runtime
            .derive(
                &runtime
                    .compile_derivation(&candidate_derivation(LICENCE_DERIVATION))
                    .expect("licence derivation compiles"),
                &licence_facts,
                &json!({}),
                context(
                    json!({
                        "active_state": "CURRENT",
                        "expiry_buckets": [
                            bucket_parameter("-365000", "0", "expired"),
                            bucket_parameter("0", "31", "within-30-days"),
                            bucket_parameter("31", "91", "within-90-days"),
                            bucket_parameter("91", "365001", "later")
                        ]
                    }),
                    BTreeMap::new(),
                ),
            )
            .expect("licence derives");
        assert!(matches!(&licence[0].value, DerivedValue::Json(value) if value == &json!(true)));
        assert!(
            matches!(&licence[1].value, DerivedValue::Json(value) if value == &json!("within-30-days"))
        );

        let relationship_facts = matched_facts(
            &runtime,
            RELATIONSHIP_EXTRACTION,
            json!({
                "total": 1,
                "records": [{
                    "returned_child_reference": "synthetic-child-record-001",
                    "parent_references": ["synthetic-parent-reference-001"],
                    "reference_namespace": "urn:example:fixture:person-reference",
                    "relationship_set_contract": "urn:example:fixture:legal-parent-set:v1",
                    "relationship_set_complete": true
                }]
            }),
        );
        let relationship = runtime
            .derive(
                &runtime
                    .compile_derivation(&candidate_derivation(RELATIONSHIP_DERIVATION))
                    .expect("relationship derivation compiles"),
                &relationship_facts,
                &json!({
                    "child": {
                        "profile": "civil-record-reference-v1",
                        "values": {"record_reference": "synthetic-child-record-001"}
                    },
                    "candidate-parent": {
                        "profile": "person-reference-v1",
                        "values": {"person_reference": "synthetic-parent-reference-001"}
                    }
                }),
                context(
                    json!({
                        "matching_policy": "exact-opaque-reference-membership-v1",
                        "candidate_reference_namespace": "urn:example:fixture:person-reference",
                        "relationship_set_contract": "urn:example:fixture:legal-parent-set:v1",
                        "legal_authority_attestation": "urn:example:fixture:governance:legal-parent-register:v1"
                    }),
                    BTreeMap::new(),
                ),
            )
            .expect("relationship derives");
        assert!(
            matches!(&relationship[0].value, DerivedValue::Json(value) if value == &json!(true))
        );
    }

    #[test]
    fn protected_seed_has_no_comparison_or_string_conversion_capability() {
        let runtime = runtime();
        for expression in [
            "{ let seed = entity_reference_seed(facts.seed); seed == seed }",
            "{ let seed = entity_reference_seed(facts.seed); seed.to_string() }",
            "{ let seed = entity_reference_seed(facts.seed); debug(seed) }",
        ] {
            let source = format!(
                "fn derive(facts, selectors, evaluation_context) {{ [#{{ concept_id: \"x\", value: {expression} }}] }}"
            );
            match runtime.compile_derivation(&source) {
                Ok(script) => assert!(matches!(
                    runtime.derive(
                        &script,
                        &BTreeMap::from([("seed".to_string(), json!("protected-canary"))]),
                        &json!({}),
                        context(json!({}), BTreeMap::new())
                    ),
                    Err(RhaiRuntimeError::Invocation)
                )),
                Err(RhaiRuntimeError::Compilation) => {}
                Err(error) => panic!("unexpected compilation result: {error}"),
            }
        }
    }

    #[test]
    fn list_contains_validates_every_element_before_any_answer() {
        for unsupported in [
            Dynamic::UNIT,
            Dynamic::from(Map::new()),
            Dynamic::from(Array::new()),
            Dynamic::from(1.5_f64),
            Dynamic::from(EntityReferenceSeed::new("seed").expect("seed")),
        ] {
            assert!(
                list_contains(
                    vec![Dynamic::from("A"), unsupported.clone()],
                    Dynamic::from("A")
                )
                .is_err(),
                "a match before an invalid element answered instead of failing"
            );
            assert!(list_contains(
                vec![unsupported.clone(), Dynamic::from("A")],
                Dynamic::from("A")
            )
            .is_err());
            assert!(
                set_contains(vec![Dynamic::from("A"), unsupported], Dynamic::from("A")).is_err()
            );
        }

        assert!(list_contains(
            vec![Dynamic::from("A"), Dynamic::from("A")],
            Dynamic::from("A")
        )
        .expect("duplicates are containment, not a set"));

        let mixed = vec![
            Dynamic::from(1_i64),
            Dynamic::from("1"),
            Dynamic::from(true),
        ];
        for needle in [
            Dynamic::from(1_i64),
            Dynamic::from("1"),
            Dynamic::from(true),
        ] {
            assert!(list_contains(mixed.clone(), needle).expect("valid scalars"));
        }
        for absent in [
            Dynamic::from(2_i64),
            Dynamic::from("true"),
            Dynamic::from(false),
        ] {
            assert!(!list_contains(mixed.clone(), absent).expect("valid scalars"));
        }

        let decimals = vec![Dynamic::from(Decimal::parse("1.25").expect("decimal"))];
        assert!(list_contains(
            decimals.clone(),
            Dynamic::from(Decimal::parse("1.25").expect("decimal"))
        )
        .expect("exact decimal comparison"));
        assert!(!list_contains(
            decimals.clone(),
            Dynamic::from(Decimal::parse("1.26").expect("decimal"))
        )
        .expect("exact decimal comparison"));
        assert!(!list_contains(
            vec![Dynamic::from(integer_to_decimal(1))],
            Dynamic::from(1_i64)
        )
        .expect("decimal and integer stay distinct"));

        assert!(list_contains(
            vec![Dynamic::from("A"); MAXIMUM_ARRAY_ITEMS + 1],
            Dynamic::from("A")
        )
        .is_err());
        assert!(list_contains(vec![Dynamic::from("A")], Dynamic::UNIT).is_err());
    }

    #[test]
    fn negative_array_indexes_fail_instead_of_selecting_from_the_end() {
        let runtime = runtime();
        let facts = || BTreeMap::from([("values".to_string(), json!(["first", "last"]))]);
        let derivation = |index: &str| {
            format!(
                r#"fn derive(facts, selectors, evaluation_context) {{
                    let position = {index};
                    [#{{ concept_id: "x", value: facts.values[position] }}]
                }}"#
            )
        };

        let computed_negative = runtime
            .compile_derivation(&derivation(
                "compare_dates(evaluation_context.legal_local_date, parse_date(\"2100-01-01\"))",
            ))
            .expect("computed index compiles");
        assert!(
            matches!(
                runtime.derive(
                    &computed_negative,
                    &facts(),
                    &json!({}),
                    context(json!({}), BTreeMap::new())
                ),
                Err(RhaiRuntimeError::Invocation)
            ),
            "a computed negative index selected from the end"
        );

        let computed_forward = runtime
            .compile_derivation(&derivation(
                "compare_dates(parse_date(\"2100-01-01\"), evaluation_context.legal_local_date)",
            ))
            .expect("computed index compiles");
        let values = runtime
            .derive(
                &computed_forward,
                &facts(),
                &json!({}),
                context(json!({}), BTreeMap::new()),
            )
            .expect("a non-negative computed index still resolves");
        assert!(matches!(&values[0].value, DerivedValue::Json(value) if value == &json!("last")));

        let computed_key = runtime
            .compile_extraction(
                r#"fn extract(source_response, parameters) {
                    let field = parameters.field;
                    #{ outcome: "match", facts: #{ code: source_response["record"][field] } }
                }"#,
            )
            .expect("computed map key compiles");
        assert_eq!(
            runtime.extract(
                &computed_key,
                &json!({"record": {"code": "A"}}),
                &json!({"field": "code"}),
                &|_: &Value| true,
            ),
            Ok(LookupResult::Match(BTreeMap::from([(
                "code".to_string(),
                json!("A")
            )])))
        );

        assert_eq!(
            runtime
                .compile_derivation(&derivation("0"))
                .and_then(|script| runtime
                    .compile_derivation(
                        "fn derive(facts, selectors, evaluation_context) { [#{ concept_id: \"x\", value: facts.values[-1] }] }",
                    )
                    .map(|_| script))
                .unwrap_err(),
            RhaiRuntimeError::Compilation
        );
        assert!(
            runtime
                .compile_derivation(
                    r#"fn derive(facts, selectors, evaluation_context) {
                        let offsets = [-1, 0];
                        [#{ concept_id: "x", value: list_contains(offsets, 0) }]
                    }"#,
                )
                .is_ok(),
            "a negative number inside an array literal is not an index"
        );
    }

    #[test]
    fn script_scanner_agrees_with_rhai_string_comment_and_pointer_tokenization() {
        let runtime = runtime();
        for rejected in [
            // Rhai reads #"A"B"# as one raw string; a scanner that treats every quote as a
            // plain delimiter desynchronizes and hides the code between two raw strings.
            "let a = #\"A\"B\"#; parameters.call(); let c = #\"D\"E\"#;",
            "let a = #\"raw\"#;",
            "let a = ##\"raw \"# still raw\"##;",
            "let a = `interpolated ${parameters}`;",
            "let a = Fn(\"helper\");",
            "parameters.call();",
            "parameters.curry(1);",
            "let a = parameters.values[-1];",
            "let a = parameters.values[ - 1];",
            "let a = 1; /* unterminated",
            "let a = __evidence_index(1);",
            // Rhai indexes a block or an if chain in operand position, so its closing
            // brace ends a value that a byte scanner cannot distinguish from the closing
            // brace of a statement block.
            "let v = [10, 20]; let a = if true { v } else { v }[-1];",
            "let a = if true { 1 } else { 2 };",
            "let a = { 1 };",
        ] {
            let source = format!(
                "fn prepare(selectors, parameters) {{ {rejected} #{{ query: [], body: () }} }}"
            );
            assert!(
                runtime.compile_preparation(&source).is_err(),
                "accepted: {rejected}"
            );
        }
        for accepted in [
            "// Fn(\"helper\") and values[-1]\n",
            "/* Fn(\"helper\") and values[-1] */",
            "let a = \"values[-1] Fn\";",
            "let a = 'x';",
            "let a = [-1, 0];",
            "let a = #{ inner: [1] }[\"inner\"][0];",
            // A statement block is followed by an array literal, not by an index.
            "if true { let b = 1; }\n [-1, 0];",
            "for x in [1, 2] { let b = x; }",
            "if true { let b = 1; } else if false { let b = 2; }",
        ] {
            let source = format!(
                "fn prepare(selectors, parameters) {{ {accepted} #{{ query: [], body: () }} }}"
            );
            assert!(
                runtime.compile_preparation(&source).is_ok(),
                "rejected: {accepted}"
            );
        }
        assert_eq!(
            runtime
                .compile_preparation(
                    "let leaked = 1; fn prepare(selectors, parameters) { #{ query: [], body: () } }",
                )
                .unwrap_err(),
            RhaiRuntimeError::Compilation
        );

        // Only index operands are rewritten, and every one of them is.
        assert_eq!(
            guarded_script_source(
                "fn f(a) { let b = a[\"k\"][0]; let c = [1, 2]; let d = #{ k: [1] }[\"k\"]; }"
            )
            .expect("reviewed"),
            "fn f(a) { let b = a[__evidence_index(\"k\")][__evidence_index(0)]; \
             let c = [1, 2]; let d = #{ k: [1] }[__evidence_index(\"k\")]; }"
        );
        assert_eq!(
            guarded_script_source("fn f(a) { let b = a[a[\"i\"]]; }").expect("reviewed"),
            "fn f(a) { let b = a[__evidence_index(a[__evidence_index(\"i\")])]; }"
        );
    }

    #[test]
    fn public_derived_values_reject_ordinary_floats() {
        let runtime = runtime();
        for float in [
            "1.5",
            "1.0",
            "[1.5]",
            "#{ ratio: 1.5 }",
            "0.0 / 0.0",
            "1.5 + 2.0",
        ] {
            let source =
                format!("fn derive(facts, selectors, evaluation_context) {{ [#{{ concept_id: \"x\", value: {float} }}] }}");
            let script = runtime.compile_derivation(&source).expect("compiles");
            assert!(
                matches!(
                    runtime.derive(
                        &script,
                        &BTreeMap::new(),
                        &json!({}),
                        context(json!({}), BTreeMap::new())
                    ),
                    Err(RhaiRuntimeError::DerivationResult)
                ),
                "ordinary float accepted at the derivation output gate: {float}"
            );
        }

        let declared = runtime
            .compile_derivation(
                r#"fn derive(facts, selectors, evaluation_context) {
                    [
                        #{ concept_id: "integer", value: 2 },
                        #{ concept_id: "exact", value: decimal("1.25") }
                    ]
                }"#,
            )
            .expect("compiles");
        let values = runtime
            .derive(
                &declared,
                &BTreeMap::new(),
                &json!({}),
                context(json!({}), BTreeMap::new()),
            )
            .expect("declared numeric forms remain available");
        assert!(matches!(&values[0].value, DerivedValue::Json(value) if value == &json!(2)));
        assert!(
            matches!(&values[1].value, DerivedValue::Decimal(value) if value.canonical() == "1.25")
        );

        let extraction = runtime
            .compile_extraction(
                "fn extract(source_response, parameters) { #{ outcome: \"match\", facts: #{ ratio: source_response.ratio } } }",
            )
            .expect("compiles");
        assert_eq!(
            runtime.extract(
                &extraction,
                &json!({"ratio": 1.25}),
                &json!({}),
                &|_: &Value| true
            ),
            Ok(LookupResult::Match(BTreeMap::from([(
                "ratio".to_string(),
                json!(1.25)
            )])))
        );

        let limits = request_limits(
            RequestPartRequirement::Optional,
            RequestPartRequirement::Optional,
        );
        let preparation = runtime
            .compile_preparation(
                "fn prepare(selectors, parameters) { #{ query: [], body: #{ ratio: 1.25 } } }",
            )
            .expect("compiles");
        assert_eq!(
            runtime
                .prepare(&preparation, &json!({}), &json!({}), &limits)
                .expect("finite adapter floats remain available")
                .body,
            Some(json!({"ratio": 1.25}))
        );
        let non_finite = runtime
            .compile_preparation(
                "fn prepare(selectors, parameters) { #{ query: [], body: #{ ratio: 0.0 / 0.0 } } }",
            )
            .expect("compiles");
        assert_eq!(
            runtime.prepare(&non_finite, &json!({}), &json!({}), &limits),
            Err(RhaiRuntimeError::PreparationResult)
        );
    }

    #[test]
    fn out_of_range_json_integer_tokens_fail_before_rhai() {
        let runtime = runtime();
        let script = runtime
            .compile_extraction(
                "fn extract(source_response, parameters) { #{ outcome: \"no_match\" } }",
            )
            .expect("compiles");
        let response = |token: &str| {
            serde_json::from_str::<Value>(&format!("{{\"value\": {token}}}")).expect("parses")
        };
        for accepted in [
            "0",
            "9223372036854775807",
            "-9223372036854775808",
            "1.25",
            "1e3",
        ] {
            assert_eq!(
                runtime.extract(&script, &response(accepted), &json!({}), &|_: &Value| true),
                Ok(LookupResult::NoMatch),
                "{accepted}"
            );
        }
        for rejected in [
            "9223372036854775808",
            "18446744073709551615",
            "99999999999999999999999",
            "1e30",
        ] {
            assert_eq!(
                runtime.extract(&script, &response(rejected), &json!({}), &|_: &Value| true),
                Err(RhaiRuntimeError::InputBound),
                "{rejected}"
            );
        }
        assert_eq!(
            runtime.extract(
                &script,
                &json!({"value": "99999999999999999999999"}),
                &json!({}),
                &|_: &Value| true
            ),
            Ok(LookupResult::NoMatch),
            "an identifier outside the signed 64-bit range must arrive as a string"
        );

        let derivation = runtime
            .compile_derivation(
                "fn derive(facts, selectors, evaluation_context) { [#{ concept_id: \"x\", value: true }] }",
            )
            .expect("compiles");
        assert!(matches!(
            runtime.derive(
                &derivation,
                &BTreeMap::from([(
                    "value".to_string(),
                    response("99999999999999999999999")["value"].clone()
                )]),
                &json!({}),
                context(json!({}), BTreeMap::new())
            ),
            Err(RhaiRuntimeError::InputBound)
        ));
    }

    #[test]
    fn required_unavailability_carries_no_supplied_code_into_any_surface() {
        let runtime = runtime();
        for code in ["required_fact_missing", "other_missing_input_9"] {
            let source = format!(
                "fn derive(facts, selectors, evaluation_context) {{ [#{{ concept_id: \"x\", value: required(facts.absent, \"{code}\") }}] }}"
            );
            let script = runtime.compile_derivation(&source).expect("compiles");
            let error = runtime
                .derive(
                    &script,
                    &BTreeMap::new(),
                    &json!({}),
                    context(json!({}), BTreeMap::new()),
                )
                .expect_err("unavailable");
            assert_eq!(error, RhaiRuntimeError::Unavailable);
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains(code), "supplied code reached a surface");
        }

        // A code that fails review validation stops before the unavailable signal.
        let unsafe_code = runtime
            .compile_derivation(
                "fn derive(facts, selectors, evaluation_context) { [#{ concept_id: \"x\", value: required(facts.absent, \"Protected Value\") }] }",
            )
            .expect("compiles");
        assert!(matches!(
            runtime.derive(
                &unsafe_code,
                &BTreeMap::new(),
                &json!({}),
                context(json!({}), BTreeMap::new())
            ),
            Err(RhaiRuntimeError::Invocation)
        ));
        assert!(required(Dynamic::from(1_i64), "Protected Value").is_err());
        assert!(required(Dynamic::from(1_i64), "").is_err());
        assert!(required(Dynamic::from(1_i64), "safe_code").is_ok());
    }

    fn boundary(minimum: &str, maximum: &str, code: &str) -> Dynamic {
        let mut map = Map::new();
        map.insert(
            "minimumInclusive".into(),
            Dynamic::from(Decimal::parse(minimum).expect("decimal")),
        );
        map.insert(
            "maximumExclusive".into(),
            Dynamic::from(Decimal::parse(maximum).expect("decimal")),
        );
        map.insert("code".into(), Dynamic::from(code.to_string()));
        Dynamic::from(map)
    }

    fn bucket_parameter(minimum: &str, maximum: &str, code: &str) -> Value {
        json!({
            "minimumInclusive": {"type": "decimal", "value": minimum},
            "maximumExclusive": {"type": "decimal", "value": maximum},
            "code": code
        })
    }

    fn matched_facts(
        runtime: &RhaiRuntime,
        source: &str,
        response: Value,
    ) -> BTreeMap<String, Value> {
        let label = if source == ADULT_EXTRACTION {
            "adult"
        } else if source == RESIDENCE_EXTRACTION {
            "residence"
        } else if source == LICENCE_EXTRACTION {
            "licence"
        } else {
            "relationship"
        };
        let script = runtime
            .compile_extraction(&candidate_extraction(source))
            .expect("extraction compiles");
        let parameters = match label {
            "licence" => {
                json!({"requestedFields": "licence_state,valid_from,valid_until", "resultLimit": "2"})
            }
            "relationship" => json!({
                "requestedFields": [
                    "returned_child_reference",
                    "parent_references",
                    "reference_namespace",
                    "relationship_set_contract",
                    "relationship_set_complete"
                ],
                "resultLimit": 2,
                "referenceNamespace": "urn:example:fixture:person-reference",
                "relationshipSetContract": "urn:example:fixture:legal-parent-set:v1",
                "relationshipSetComplete": true
            }),
            _ => json!({}),
        };
        match runtime
            .extract(&script, &response, &parameters, &|_: &Value| true)
            .unwrap_or_else(|error| panic!("{label} extraction failed: {error}"))
        {
            LookupResult::Match(facts) => facts,
            other => panic!("expected match, got {other:?}"),
        }
    }

    fn candidate_extraction(source: &str) -> String {
        source.replacen(
            "fn extract(source_response)",
            "fn extract(source_response, parameters)",
            1,
        )
    }

    fn candidate_derivation(source: &str) -> String {
        source.replacen(
            "fn derive(facts, evaluation_context)",
            "fn derive(facts, selectors, evaluation_context)",
            1,
        )
    }
}
