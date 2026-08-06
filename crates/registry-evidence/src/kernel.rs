//! Generic offline Evidence evaluation and core-owned output projection.
//!
//! This module deliberately knows nothing about an acceptance case or source
//! product. It joins one captured bundle revision to the hardened Rhai runtime,
//! validates the complete declared Supported Value set, and constructs the
//! unsigned Evidence payload that the production release path later signs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use chrono_tz::Tz;
use jsonschema::{Draft, JSONSchema};
use serde_json::{Map as JsonMap, Value};
use thiserror::Error;

use crate::binding::entity_reference;
use crate::bundle::{Bundle, Codelist};
use crate::config::{
    ConceptConfig, ConceptForm, PreparationChannelPolicy, PreparationLimits, RequirementConfig,
};
use crate::model::{
    BucketForm, BucketValue, EntityReferenceForm, EntityReferenceValue, Evidence,
    EvidenceObjectType, LookupResult, PublicValue, ScalarOrEntityReference, StructuredValue,
    StructuredValueForm, SubjectBinding, SupportedValue,
};
use crate::rhai_runtime::{
    CalendarDate, CodelistHandle, CompiledDerivation, CompiledExtraction, CompiledPreparation,
    DerivedConceptValue, DerivedValue, EvaluationContext, LegalLocalTime, RequestPartRequirement,
    RequestParts, RequestPartsBounds, RequestPartsLimits, RhaiRuntime, RhaiRuntimeError,
    UtcInstant, MAXIMUM_RESULT_BYTES,
};
use crate::values::Decimal;

const MAXIMUM_PUBLIC_STRING_BYTES: usize = 1_024;
const MAXIMUM_BUCKET_CODE_BYTES: usize = 128;
const MAXIMUM_EVIDENCE_IDENTIFIER_BYTES: usize = 512;
const DEFAULT_MAXIMUM_QUERY_PAIRS: usize = 64;
const DEFAULT_MAXIMUM_QUERY_NAME_BYTES: usize = 64;
const DEFAULT_MAXIMUM_QUERY_VALUE_BYTES: usize = 4_096;
const DEFAULT_MAXIMUM_JSON_DEPTH: usize = 32;
const DEFAULT_MAXIMUM_COLLECTION_ITEMS: usize = 256;
const DEFAULT_MAXIMUM_STRING_BYTES: usize = 16_384;
const DEFAULT_MAXIMUM_NORMALIZED_BYTES: usize = 65_536;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    #[error("the Evidence bundle cannot initialize the offline kernel")]
    Bundle,
    #[error("the requested Evidence requirement is unavailable")]
    Requirement,
    #[error("the Evidence extraction failed")]
    Extraction,
    /// A uniquely resolved record reached derivation with missing, mistyped,
    /// or inconsistent inputs. Publicly this collapses with the unresolved
    /// lookup classes so callers cannot learn that a record exists.
    #[error("the Evidence derivation inputs are unresolved")]
    DerivationInput,
    #[error("the Evidence request preparation failed")]
    Preparation,
    #[error("the source response violates its fixed protocol contract")]
    SourceProtocol,
    #[error("the Evidence script failed")]
    Script,
    #[error("the derived Evidence values violate the requirement contract")]
    Output,
    #[error("the Evidence payload metadata is invalid")]
    Evidence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KernelOutcome {
    Match(ValidatedValues),
    NoMatch,
    Ambiguous,
}

/// Values that have passed the complete requirement output gate.
///
/// The inner vector is intentionally not publicly constructible or mutable, so
/// Evidence construction cannot be invoked with an unchecked `PublicValue`.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedValues(Vec<SupportedValue>);

impl ValidatedValues {
    pub fn as_slice(&self) -> &[SupportedValue] {
        &self.0
    }
}

impl std::fmt::Debug for ValidatedValues {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedValues")
            .field(
                "concept_identifiers",
                &self
                    .0
                    .iter()
                    .map(|value| value.provides_value_for.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Runtime-owned inputs needed to project protected derivation values.
pub struct ValueProjection<'a> {
    pub audience: &'a str,
    pub binding_key: &'a [u8],
    pub binding_key_version: u32,
}

/// Core-owned envelope inputs supplied by the authenticated release pipeline.
pub struct EvidenceConstruction<'a> {
    pub evidence_id: &'a str,
    /// Exact caller nonce to echo. It is copied verbatim into the payload and
    /// is not part of the subject binding, audit, or any diagnostic surface.
    pub request_nonce: &'a str,
    pub purpose: &'a str,
    pub audience: &'a str,
    pub issued_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub subjects: Vec<SubjectBinding>,
}

fn compile_request_parts_limits(
    configured: &PreparationLimits,
) -> Result<RequestPartsLimits, KernelError> {
    fn requirement(policy: PreparationChannelPolicy) -> RequestPartRequirement {
        match policy {
            PreparationChannelPolicy::Required => RequestPartRequirement::Required,
            PreparationChannelPolicy::Allowed => RequestPartRequirement::Optional,
            PreparationChannelPolicy::Forbidden => RequestPartRequirement::Forbidden,
        }
    }

    fn bounded(value: Option<u64>, default: usize) -> Result<usize, KernelError> {
        value
            .map(usize::try_from)
            .transpose()
            .map_err(|_| KernelError::Bundle)
            .map(|value| value.unwrap_or(default))
    }

    RequestPartsLimits::new(
        requirement(configured.query),
        requirement(configured.json_body),
        RequestPartsBounds {
            maximum_query_pairs: bounded(
                configured.maximum_query_pairs,
                DEFAULT_MAXIMUM_QUERY_PAIRS,
            )?,
            maximum_query_name_bytes: bounded(
                configured.maximum_query_name_bytes,
                DEFAULT_MAXIMUM_QUERY_NAME_BYTES,
            )?,
            maximum_query_value_bytes: bounded(
                configured.maximum_query_value_bytes,
                DEFAULT_MAXIMUM_QUERY_VALUE_BYTES,
            )?,
            maximum_json_depth: bounded(configured.maximum_json_depth, DEFAULT_MAXIMUM_JSON_DEPTH)?,
            maximum_collection_items: bounded(
                configured.maximum_collection_items,
                DEFAULT_MAXIMUM_COLLECTION_ITEMS,
            )?,
            maximum_string_bytes: bounded(
                configured.maximum_string_bytes,
                DEFAULT_MAXIMUM_STRING_BYTES,
            )?,
            maximum_normalized_bytes: bounded(
                configured.maximum_normalized_bytes,
                DEFAULT_MAXIMUM_NORMALIZED_BYTES,
            )?,
        },
    )
    .map_err(|_| KernelError::Bundle)
}

/// A kernel compiled entirely from the bytes captured in one immutable bundle.
pub struct OfflineKernel {
    bundle: Arc<Bundle>,
    runtime: RhaiRuntime,
    preparations: BTreeMap<String, CompiledPreparation>,
    extractions: BTreeMap<String, CompiledExtraction>,
    request_parts_limits: BTreeMap<String, RequestPartsLimits>,
    derivations: BTreeMap<String, CompiledDerivation>,
    response_schemas: BTreeMap<String, JSONSchema>,
    fact_schemas: BTreeMap<String, JSONSchema>,
    reviewed_schemas: BTreeMap<String, JSONSchema>,
    codelist_handles: BTreeMap<String, BTreeMap<String, CodelistHandle>>,
}

impl std::fmt::Debug for OfflineKernel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineKernel")
            .field("configuration_revision", &self.bundle.revision())
            .field("source_count", &self.extractions.len())
            .field("requirement_count", &self.derivations.len())
            .finish()
    }
}

impl OfflineKernel {
    pub fn compile(bundle: Arc<Bundle>) -> Result<Self, KernelError> {
        let runtime = RhaiRuntime::new();
        let mut preparations = BTreeMap::new();
        let mut extractions = BTreeMap::new();
        let mut request_parts_limits = BTreeMap::new();
        let mut response_schemas = BTreeMap::new();
        let mut fact_schemas = BTreeMap::new();
        for (source_id, source) in bundle.config.sources.iter() {
            let preparation = bundle
                .script(&source.request.prepare_script)
                .ok_or(KernelError::Bundle)?;
            let compiled_preparation = runtime
                .compile_preparation(&preparation.source)
                .map_err(|_| KernelError::Bundle)?;
            preparations.insert(source_id.to_owned(), compiled_preparation);

            let extraction = bundle
                .script(&source.extract_script)
                .ok_or(KernelError::Bundle)?;
            let compiled_extraction = runtime
                .compile_extraction(&extraction.source)
                .map_err(|_| KernelError::Bundle)?;
            extractions.insert(source_id.to_owned(), compiled_extraction);
            request_parts_limits.insert(
                source_id.to_owned(),
                compile_request_parts_limits(&source.request.preparation_limits)?,
            );

            let response_schema = bundle
                .fact_schema(&source.response_schema)
                .ok_or(KernelError::Bundle)?;
            response_schemas.insert(source_id.to_owned(), compile_schema(response_schema)?);

            let schema = bundle
                .fact_schema(&source.fact_schema)
                .ok_or(KernelError::Bundle)?;
            let compiled_schema = compile_schema(schema)?;
            fact_schemas.insert(source_id.to_owned(), compiled_schema);
        }

        let mut derivations = BTreeMap::new();
        for requirement in &bundle.config.requirements {
            let script = bundle
                .script(&requirement.derivation.script)
                .ok_or(KernelError::Bundle)?;
            let compiled = runtime
                .compile_derivation(&script.source)
                .map_err(|_| KernelError::Bundle)?;
            derivations.insert(requirement.id.clone(), compiled);
        }

        let mut reviewed_schemas = BTreeMap::new();
        for schema in bundle.fact_schemas.values() {
            if let Some(identifier) = schema.get("$id").and_then(Value::as_str) {
                if reviewed_schemas
                    .insert(identifier.to_owned(), compile_schema(schema)?)
                    .is_some()
                {
                    return Err(KernelError::Bundle);
                }
            }
        }

        let codelist_handles = bundle
            .config
            .requirements
            .iter()
            .map(|requirement| {
                build_codelist_handles(&bundle, requirement)
                    .map(|handles| (requirement.id.clone(), handles))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            bundle,
            runtime,
            preparations,
            extractions,
            request_parts_limits,
            derivations,
            response_schemas,
            fact_schemas,
            reviewed_schemas,
            codelist_handles,
        })
    }

    /// Run the reviewed preparation script after authorization and access audit.
    pub fn prepare(
        &self,
        requirement_id: &str,
        selectors: &Value,
    ) -> Result<RequestParts, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        let source = self
            .bundle
            .config
            .sources
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        let script = self
            .preparations
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        let limits = self
            .request_parts_limits
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        let parameters = serde_json::to_value(&source.request.adapter_parameters)
            .map_err(|_| KernelError::Bundle)?;
        self.runtime
            .prepare(script, selectors, &parameters, limits)
            .map_err(|_| KernelError::Preparation)
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    pub fn requirement(&self, requirement_id: &str) -> Option<&RequirementConfig> {
        self.bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)
    }

    /// Run only the closed extraction ABI over one already-bounded JSON response.
    pub fn extract(
        &self,
        requirement_id: &str,
        source_response: &Value,
    ) -> Result<LookupResult, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        let script = self
            .extractions
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        let schema = self
            .fact_schemas
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        let source = self
            .bundle
            .config
            .sources
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        // The declared response shape is checked in Rust before any script sees
        // the response, so extraction maps a response it can rely on and a
        // provider that breaks its protocol fails closed the same way whether
        // or not the script happens to test for it.
        let response_schema = self
            .response_schemas
            .get(&requirement.source)
            .ok_or(KernelError::Bundle)?;
        if let Err(errors) = response_schema.validate(source_response) {
            report_response_shape_rejection(
                &requirement.source,
                source.response_schema.as_str(),
                errors,
            );
            return Err(KernelError::SourceProtocol);
        }
        let parameters = serde_json::to_value(&source.request.adapter_parameters)
            .map_err(|_| KernelError::Bundle)?;
        self.runtime
            .extract(script, source_response, &parameters, schema)
            .map_err(|error| match error {
                RhaiRuntimeError::ExtractionResult | RhaiRuntimeError::FactSchema => {
                    KernelError::Extraction
                }
                RhaiRuntimeError::Unavailable => KernelError::Extraction,
                RhaiRuntimeError::SourceProtocol => KernelError::SourceProtocol,
                RhaiRuntimeError::Compilation
                | RhaiRuntimeError::EntryPoint
                | RhaiRuntimeError::Invocation
                | RhaiRuntimeError::InputBound
                | RhaiRuntimeError::AdapterInput
                | RhaiRuntimeError::PreparationResult
                | RhaiRuntimeError::DerivationResult
                | RhaiRuntimeError::DerivationInput
                | RhaiRuntimeError::EvaluationContext
                | RhaiRuntimeError::Codelist => KernelError::Script,
            })
    }

    /// Derive and gate the exact Supported Value set for one unique match.
    pub fn derive_and_validate(
        &self,
        requirement_id: &str,
        facts: &BTreeMap<String, Value>,
        observed_at: DateTime<Utc>,
        projection: ValueProjection<'_>,
    ) -> Result<ValidatedValues, KernelError> {
        self.derive_and_validate_with_selectors(
            requirement_id,
            facts,
            &Value::Object(JsonMap::new()),
            observed_at,
            projection,
        )
    }

    /// Derive with the exact requirement-declared selector subset.
    pub fn derive_and_validate_with_selectors(
        &self,
        requirement_id: &str,
        facts: &BTreeMap<String, Value>,
        selectors: &Value,
        observed_at: DateTime<Utc>,
        projection: ValueProjection<'_>,
    ) -> Result<ValidatedValues, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        let script = self
            .derivations
            .get(requirement_id)
            .ok_or(KernelError::Bundle)?;
        let evaluation_context = self.evaluation_context(requirement, observed_at)?;
        let derived = self
            .runtime
            .derive(script, facts, selectors, evaluation_context)
            .map_err(|error| match error {
                RhaiRuntimeError::Unavailable => KernelError::Extraction,
                RhaiRuntimeError::DerivationInput => KernelError::DerivationInput,
                RhaiRuntimeError::SourceProtocol => KernelError::Script,
                _ => KernelError::Script,
            })?;
        self.validate_values(requirement_id, derived, projection)
    }

    /// Run the complete offline lookup and derivation path.
    pub fn evaluate(
        &self,
        requirement_id: &str,
        source_response: &Value,
        observed_at: DateTime<Utc>,
        projection: ValueProjection<'_>,
    ) -> Result<KernelOutcome, KernelError> {
        self.evaluate_with_selectors(
            requirement_id,
            source_response,
            &Value::Object(JsonMap::new()),
            observed_at,
            projection,
        )
    }

    /// Run lookup and derivation with the exact selector subset declared for derivation.
    pub fn evaluate_with_selectors(
        &self,
        requirement_id: &str,
        source_response: &Value,
        selectors: &Value,
        observed_at: DateTime<Utc>,
        projection: ValueProjection<'_>,
    ) -> Result<KernelOutcome, KernelError> {
        match self.extract(requirement_id, source_response)? {
            LookupResult::Match(facts) => self
                .derive_and_validate_with_selectors(
                    requirement_id,
                    &facts,
                    selectors,
                    observed_at,
                    projection,
                )
                .map(KernelOutcome::Match),
            LookupResult::NoMatch => Ok(KernelOutcome::NoMatch),
            LookupResult::Ambiguous => Ok(KernelOutcome::Ambiguous),
        }
    }

    /// Apply the output gate to values produced by the hardened Rhai ABI.
    pub fn validate_values(
        &self,
        requirement_id: &str,
        derived: Vec<DerivedConceptValue>,
        projection: ValueProjection<'_>,
    ) -> Result<ValidatedValues, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        gate_values(
            requirement,
            derived,
            projection,
            &self.bundle.codelists,
            &self.reviewed_schemas,
        )
    }

    /// Construct the exact unsigned payload after output validation.
    pub fn construct_evidence(
        &self,
        requirement_id: &str,
        values: ValidatedValues,
        input: EvidenceConstruction<'_>,
    ) -> Result<Evidence, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        validate_evidence_inputs(requirement, values.as_slice(), &input)?;
        let valid_until = input
            .issued_at
            .checked_add_signed(Duration::seconds(
                i64::try_from(requirement.validity_seconds).map_err(|_| KernelError::Evidence)?,
            ))
            .ok_or(KernelError::Evidence)
            .map(format_utc)?;

        Ok(Evidence {
            schema: crate::EVIDENCE_SCHEMA_V1.to_owned(),
            assurance_profile: self.bundle.config.assurance_profile,
            request_nonce: input.request_nonce.to_owned(),
            id: input.evidence_id.to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: requirement.id.clone(),
            is_conformant_to: requirement.evidence_type.clone(),
            issued_by: self.bundle.config.issuer.id.clone(),
            provided_by: self.bundle.config.service.provider_id.clone(),
            issued_at: format_utc(input.issued_at),
            observed_at: format_utc(input.observed_at),
            valid_until,
            purpose: input.purpose.to_owned(),
            audience: input.audience.to_owned(),
            configuration_revision: self.bundle.revision().to_owned(),
            subjects: input.subjects,
            supported_values: values.0,
        })
    }

    fn evaluation_context(
        &self,
        requirement: &RequirementConfig,
        observed_at: DateTime<Utc>,
    ) -> Result<EvaluationContext, KernelError> {
        let timezone = requirement
            .observation_timezone
            .as_deref()
            .map(Tz::from_str)
            .transpose()
            .map_err(|_| KernelError::Bundle)?
            .unwrap_or(Tz::UTC);
        let local = observed_at.with_timezone(&timezone);
        let parameters = serde_json::to_value(&requirement.derivation.parameters)
            .map_err(|_| KernelError::Bundle)?;
        EvaluationContext::new(
            UtcInstant::parse(&format_utc(observed_at)).map_err(map_context_error)?,
            CalendarDate::parse(&local.format("%Y-%m-%d").to_string())
                .map_err(map_context_error)?,
            LegalLocalTime::parse(&local.format("%H:%M:%S%:z").to_string())
                .map_err(map_context_error)?,
            &parameters,
            self.codelist_handles
                .get(&requirement.id)
                .cloned()
                .ok_or(KernelError::Bundle)?,
        )
        .map_err(map_context_error)
    }
}

fn map_context_error(_: RhaiRuntimeError) -> KernelError {
    KernelError::Bundle
}

/// How many response shape violations one rejection reports.
///
/// A rejected response is one event, and the first few violations already say
/// which member disagrees with which rule. An unbounded list would let a source
/// decide how much an operator log holds.
const REPORTED_SHAPE_VIOLATIONS: usize = 5;

/// Record which member of a projected response failed which schema rule.
///
/// The two pointers are the whole diagnosis and neither is a value. Without
/// them a stale response schema and a source that changed its protocol are the
/// same `dependency_unavailable`, which sends an operator to the provider for a
/// defect that lives in the bundle.
///
/// Nothing from the response body is recorded: the paths are members the
/// bundle's own projection selected, and the schema path is bundle text. The
/// library's own error message embeds the offending value, so it is deliberately
/// not used here.
fn report_response_shape_rejection<'a>(
    source_id: &str,
    schema_artifact: &str,
    errors: impl Iterator<Item = jsonschema::ValidationError<'a>>,
) {
    let (violations, total) = describe_response_shape_rejection(errors);
    tracing::warn!(
        target: "registry_evidence::source",
        source = source_id,
        schema = schema_artifact,
        violations = violations.join("; "),
        total_violations = total,
        "the projected source response does not match its declared response shape"
    );
}

/// Reduce validation errors to bounded, value-free violation descriptions.
///
/// Separated from the logging call so the property that matters can be asserted
/// directly: what is produced here is the only thing that reaches the log.
fn describe_response_shape_rejection<'a>(
    errors: impl Iterator<Item = jsonschema::ValidationError<'a>>,
) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    let mut total = 0usize;
    for error in errors {
        total += 1;
        if violations.len() < REPORTED_SHAPE_VIOLATIONS {
            violations.push(format!(
                "{} violates {}",
                display_pointer(&error.instance_path),
                display_pointer(&error.schema_path)
            ));
        }
    }
    (violations, total)
}

/// Render a JSON Pointer, naming the document root rather than printing nothing.
fn display_pointer(pointer: &jsonschema::paths::JSONPointer) -> String {
    let rendered = pointer.to_string();
    if rendered.is_empty() {
        "the response root".to_owned()
    } else {
        rendered
    }
}

fn compile_schema(schema: &Value) -> Result<JSONSchema, KernelError> {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| KernelError::Bundle)
}

fn build_codelist_handles(
    bundle: &Bundle,
    requirement: &RequirementConfig,
) -> Result<BTreeMap<String, CodelistHandle>, KernelError> {
    let mut paths = BTreeSet::new();
    for concept in &requirement.concepts {
        if let Some(path) = concept
            .constraints
            .get("codelist")
            .and_then(serde_norway::Value::as_str)
        {
            paths.insert(path);
        }
        if matches!(
            concept.form,
            ConceptForm::DateBucket | ConceptForm::TimeBucket
        ) {
            let scheme = constraint_str(concept, "bucketScheme")?;
            let version = constraint_str(concept, "schemeVersion")?;
            let mut matches = bundle
                .codelists
                .iter()
                .filter(|(_, codelist)| codelist.id() == scheme && codelist.version() == version);
            let (path, _) = matches.next().ok_or(KernelError::Bundle)?;
            if matches.next().is_some() {
                return Err(KernelError::Bundle);
            }
            paths.insert(path);
        }
    }

    let mut handles = BTreeMap::new();
    for path in paths {
        let codelist = bundle.codelists.get(path).ok_or(KernelError::Bundle)?;
        let name = Path::new(path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or(KernelError::Bundle)?;
        let entries = match codelist {
            Codelist::Codes { codes, .. } => codes
                .iter()
                .map(|code| (code.clone(), code.clone()))
                .collect(),
            Codelist::Mapping { entries, .. } => entries.clone(),
        };
        let handle = CodelistHandle::new(entries).map_err(|_| KernelError::Bundle)?;
        if handles.insert(name.to_owned(), handle).is_some() {
            return Err(KernelError::Bundle);
        }
    }
    Ok(handles)
}

fn gate_values(
    requirement: &RequirementConfig,
    derived: Vec<DerivedConceptValue>,
    projection: ValueProjection<'_>,
    codelists: &BTreeMap<String, Codelist>,
    reviewed_schemas: &BTreeMap<String, JSONSchema>,
) -> Result<ValidatedValues, KernelError> {
    if derived.is_empty() || derived.len() > 16 {
        return Err(KernelError::Output);
    }
    let derived_count = derived.len();
    let by_identifier = derived
        .into_iter()
        .map(|entry| (entry.concept_id, entry.value))
        .collect::<BTreeMap<_, _>>();
    if by_identifier.len() != derived_count
        || by_identifier.len() > requirement.concepts.len()
        || requirement
            .concepts
            .iter()
            .any(|concept| concept.required && !by_identifier.contains_key(&concept.id))
        || by_identifier.keys().any(|identifier| {
            !requirement
                .concepts
                .iter()
                .any(|concept| concept.id == *identifier)
        })
    {
        return Err(KernelError::Output);
    }

    let mut result = Vec::with_capacity(by_identifier.len());
    let mut total_bytes = 0usize;
    for concept in &requirement.concepts {
        let Some(value) = by_identifier.get(&concept.id) else {
            continue;
        };
        let public = validate_value(concept, value, &projection, codelists, reviewed_schemas)?;
        total_bytes = total_bytes
            .checked_add(
                serde_json::to_vec(&public)
                    .map_err(|_| KernelError::Output)?
                    .len(),
            )
            .ok_or(KernelError::Output)?;
        if total_bytes > MAXIMUM_RESULT_BYTES {
            return Err(KernelError::Output);
        }
        result.push(SupportedValue {
            provides_value_for: concept.id.clone(),
            value: public,
        });
    }
    Ok(ValidatedValues(result))
}

fn validate_value(
    concept: &ConceptConfig,
    value: &DerivedValue,
    projection: &ValueProjection<'_>,
    codelists: &BTreeMap<String, Codelist>,
    reviewed_schemas: &BTreeMap<String, JSONSchema>,
) -> Result<PublicValue, KernelError> {
    match concept.form {
        ConceptForm::Boolean => match value {
            DerivedValue::Json(Value::Bool(value)) => Ok(PublicValue::Boolean(*value)),
            _ => Err(KernelError::Output),
        },
        ConceptForm::ControlledCode | ConceptForm::ControlledCategory => {
            let text = derived_string(value)?;
            let maximum = constraint_usize(concept, "maximumBytes")?;
            validate_public_string(text, maximum)?;
            let codelist = declared_codelist(concept, codelists)?;
            if concept.form == ConceptForm::ControlledCategory
                && codelist.id() != constraint_str(concept, "categoryScheme")?
            {
                return Err(KernelError::Bundle);
            }
            if !codelist.contains_output(text) {
                return Err(KernelError::Output);
            }
            Ok(PublicValue::String(text.to_owned()))
        }
        ConceptForm::BoundedInteger => {
            let integer = match value {
                DerivedValue::Json(Value::Number(number)) => {
                    number.as_i64().ok_or(KernelError::Output)?
                }
                _ => return Err(KernelError::Output),
            };
            let minimum = constraint_i64(concept, "minimum")?;
            let maximum = constraint_i64(concept, "maximum")?;
            if !(minimum..=maximum).contains(&integer) {
                return Err(KernelError::Output);
            }
            Ok(PublicValue::Integer(integer))
        }
        ConceptForm::BoundedDecimal => {
            let decimal = match value {
                DerivedValue::Decimal(decimal) => decimal,
                _ => return Err(KernelError::Output),
            };
            let minimum = Decimal::parse(constraint_str(concept, "minimum")?)
                .map_err(|_| KernelError::Bundle)?;
            let maximum = Decimal::parse(constraint_str(concept, "maximum")?)
                .map_err(|_| KernelError::Bundle)?;
            let maximum_scale = constraint_u64(concept, "maximumScale")?;
            if u64::from(decimal.scale()) > maximum_scale
                || decimal.compare(&minimum).is_lt()
                || decimal.compare(&maximum).is_gt()
            {
                return Err(KernelError::Output);
            }
            Ok(PublicValue::String(decimal.canonical().to_owned()))
        }
        ConceptForm::DateBucket | ConceptForm::TimeBucket => {
            validate_bucket(concept, value, codelists)
        }
        ConceptForm::AudienceScopedEntityReference => {
            let seed = match value {
                DerivedValue::EntityReferenceSeed(seed) => seed,
                _ => return Err(KernelError::Output),
            };
            let reference = project_entity(concept, seed, projection)?;
            Ok(PublicValue::EntityReference(EntityReferenceValue {
                form: EntityReferenceForm::AudienceScopedEntityReference,
                reference,
            }))
        }
        ConceptForm::ControlledCodeList => {
            let values = match value {
                DerivedValue::Json(Value::Array(values)) => values,
                _ => return Err(KernelError::Output),
            };
            validate_cardinality(concept, values.len())?;
            let codelist = declared_codelist(concept, codelists)?;
            let mut unique = BTreeSet::new();
            let mut public = Vec::with_capacity(values.len());
            for item in values {
                let text = item.as_str().ok_or(KernelError::Output)?;
                validate_public_string(text, MAXIMUM_PUBLIC_STRING_BYTES)?;
                if !codelist.contains_output(text) || !unique.insert(text) {
                    return Err(KernelError::Output);
                }
                public.push(ScalarOrEntityReference::String(text.to_owned()));
            }
            Ok(PublicValue::List(public))
        }
        ConceptForm::EntityReferenceList => {
            let seeds = match value {
                DerivedValue::EntityReferenceSeedList(seeds) => seeds,
                _ => return Err(KernelError::Output),
            };
            validate_cardinality(concept, seeds.len())?;
            let mut unique = BTreeSet::new();
            let mut public = Vec::with_capacity(seeds.len());
            for seed in seeds {
                let reference = project_entity(concept, seed, projection)?;
                if !unique.insert(reference.clone()) {
                    return Err(KernelError::Output);
                }
                public.push(ScalarOrEntityReference::EntityReference(
                    EntityReferenceValue {
                        form: EntityReferenceForm::AudienceScopedEntityReference,
                        reference,
                    },
                ));
            }
            Ok(PublicValue::List(public))
        }
        ConceptForm::ReviewedStructuredValue => {
            validate_structured(concept, value, reviewed_schemas)
        }
    }
}

fn validate_bucket(
    concept: &ConceptConfig,
    value: &DerivedValue,
    codelists: &BTreeMap<String, Codelist>,
) -> Result<PublicValue, KernelError> {
    let object = match value {
        DerivedValue::Json(Value::Object(object)) => object,
        _ => return Err(KernelError::Output),
    };
    if !has_exact_json_keys(object, &["form", "scheme", "bucket"]) {
        return Err(KernelError::Output);
    }
    let expected_form = match concept.form {
        ConceptForm::DateBucket => "date-bucket",
        ConceptForm::TimeBucket => "time-bucket",
        _ => return Err(KernelError::Bundle),
    };
    let form = object["form"].as_str().ok_or(KernelError::Output)?;
    let scheme = object["scheme"].as_str().ok_or(KernelError::Output)?;
    let bucket = object["bucket"].as_str().ok_or(KernelError::Output)?;
    if form != expected_form
        || scheme != constraint_str(concept, "bucketScheme")?
        || !valid_code(bucket)
        || bucket.len() > MAXIMUM_BUCKET_CODE_BYTES
    {
        return Err(KernelError::Output);
    }
    let scheme_version = constraint_str(concept, "schemeVersion")?;
    let codelist = codelists
        .values()
        .filter(|candidate| candidate.id() == scheme && candidate.version() == scheme_version)
        .exactly_one()
        .ok_or(KernelError::Bundle)?;
    if !codelist.contains_output(bucket) {
        return Err(KernelError::Output);
    }
    Ok(PublicValue::Bucket(BucketValue {
        form: if concept.form == ConceptForm::DateBucket {
            BucketForm::DateBucket
        } else {
            BucketForm::TimeBucket
        },
        scheme: scheme.to_owned(),
        bucket: bucket.to_owned(),
    }))
}

fn validate_structured(
    concept: &ConceptConfig,
    value: &DerivedValue,
    schemas: &BTreeMap<String, JSONSchema>,
) -> Result<PublicValue, KernelError> {
    let object = match value {
        DerivedValue::Json(Value::Object(object)) => object,
        _ => return Err(KernelError::Output),
    };
    if !has_exact_json_keys(object, &["form", "schema", "fields"])
        || object["form"].as_str() != Some("reviewed-structured-value")
    {
        return Err(KernelError::Output);
    }
    let schema_id = object["schema"].as_str().ok_or(KernelError::Output)?;
    if schema_id != constraint_str(concept, "schema")? {
        return Err(KernelError::Output);
    }
    let fields = object["fields"]
        .as_object()
        .filter(|fields| !fields.is_empty() && fields.len() <= 16)
        .ok_or(KernelError::Output)?;
    let maximum = constraint_usize(concept, "maximumSerializedBytes")?;
    if serde_json::to_vec(value_as_json(value)?)
        .map_err(|_| KernelError::Output)?
        .len()
        > maximum
    {
        return Err(KernelError::Output);
    }
    let schema = schemas.get(schema_id).ok_or(KernelError::Bundle)?;
    let fields_value = Value::Object(fields.clone());
    if !schema.is_valid(&fields_value) {
        return Err(KernelError::Output);
    }
    Ok(PublicValue::Structured(StructuredValue {
        form: StructuredValueForm::ReviewedStructuredValue,
        schema: schema_id.to_owned(),
        fields: fields.clone().into_iter().collect(),
    }))
}

fn project_entity(
    concept: &ConceptConfig,
    seed: &crate::values::EntityReferenceSeed,
    projection: &ValueProjection<'_>,
) -> Result<String, KernelError> {
    let reference = entity_reference(
        projection.binding_key,
        projection.binding_key_version,
        &concept.id,
        projection.audience,
        seed.expose_for_projection(),
    )
    .map_err(|_| KernelError::Output)?;
    let maximum = if concept.constraints.contains_key("maximumBytes") {
        constraint_usize(concept, "maximumBytes")?
    } else {
        MAXIMUM_PUBLIC_STRING_BYTES
    };
    if reference.len() > maximum {
        return Err(KernelError::Output);
    }
    Ok(reference)
}

fn validate_evidence_inputs(
    requirement: &RequirementConfig,
    values: &[SupportedValue],
    input: &EvidenceConstruction<'_>,
) -> Result<(), KernelError> {
    if input.evidence_id.is_empty()
        || input.evidence_id.len() > MAXIMUM_EVIDENCE_IDENTIFIER_BYTES
        || url::Url::parse(input.evidence_id).is_err()
        || !crate::model::request_nonce_is_canonical(input.request_nonce)
        || input.audience.is_empty()
        || input.audience.len() > MAXIMUM_EVIDENCE_IDENTIFIER_BYTES
        || url::Url::parse(input.audience).is_err()
        || !requirement
            .purposes
            .iter()
            .any(|purpose| purpose == input.purpose)
        || input.issued_at < input.observed_at
        || input.subjects.len() != requirement.subject_roles.len()
        || values.is_empty()
    {
        return Err(KernelError::Evidence);
    }
    let mut roles = BTreeSet::new();
    for (configured, subject) in requirement.subject_roles.iter().zip(&input.subjects) {
        if configured.role != subject.role
            || !roles.insert(subject.role.as_str())
            || !valid_opaque_binding(&subject.binding)
        {
            return Err(KernelError::Evidence);
        }
    }
    let expected = requirement
        .concepts
        .iter()
        .filter(|concept| concept.required)
        .map(|concept| concept.id.as_str())
        .collect::<BTreeSet<_>>();
    let actual = values
        .iter()
        .map(|value| value.provides_value_for.as_str())
        .collect::<BTreeSet<_>>();
    if actual.len() != values.len()
        || !expected.is_subset(&actual)
        || actual.iter().any(|identifier| {
            !requirement
                .concepts
                .iter()
                .any(|concept| concept.id == *identifier)
        })
    {
        return Err(KernelError::Evidence);
    }
    Ok(())
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn valid_opaque_binding(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("urn:evidence:subject:v") else {
        return false;
    };
    let Some((version, encoded)) = rest.split_once('_') else {
        return false;
    };
    !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && encoded.len() == 43
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn derived_string(value: &DerivedValue) -> Result<&str, KernelError> {
    match value {
        DerivedValue::Json(Value::String(value)) => Ok(value),
        _ => Err(KernelError::Output),
    }
}

fn value_as_json(value: &DerivedValue) -> Result<&Value, KernelError> {
    match value {
        DerivedValue::Json(value) => Ok(value),
        _ => Err(KernelError::Output),
    }
}

fn validate_public_string(value: &str, declared_maximum: usize) -> Result<(), KernelError> {
    if value.is_empty()
        || value.len() > declared_maximum
        || value.len() > MAXIMUM_PUBLIC_STRING_BYTES
    {
        return Err(KernelError::Output);
    }
    Ok(())
}

fn validate_cardinality(concept: &ConceptConfig, length: usize) -> Result<(), KernelError> {
    let minimum = constraint_usize(concept, "minimumItems")?;
    let maximum = constraint_usize(concept, "maximumItems")?;
    if length < minimum || length > maximum || !constraint_bool(concept, "unique")? {
        return Err(KernelError::Output);
    }
    Ok(())
}

fn declared_codelist<'a>(
    concept: &ConceptConfig,
    codelists: &'a BTreeMap<String, Codelist>,
) -> Result<&'a Codelist, KernelError> {
    let path = constraint_str(concept, "codelist")?;
    let expected_version_key = if concept.form == ConceptForm::ControlledCategory {
        "schemeVersion"
    } else {
        "codelistVersion"
    };
    let expected_version = constraint_str(concept, expected_version_key)?;
    let codelist = codelists.get(path).ok_or(KernelError::Bundle)?;
    if codelist.version() != expected_version {
        return Err(KernelError::Bundle);
    }
    Ok(codelist)
}

fn constraint_str<'a>(concept: &'a ConceptConfig, name: &str) -> Result<&'a str, KernelError> {
    concept
        .constraints
        .get(name)
        .and_then(serde_norway::Value::as_str)
        .ok_or(KernelError::Bundle)
}

fn constraint_i64(concept: &ConceptConfig, name: &str) -> Result<i64, KernelError> {
    concept
        .constraints
        .get(name)
        .and_then(serde_norway::Value::as_i64)
        .ok_or(KernelError::Bundle)
}

fn constraint_u64(concept: &ConceptConfig, name: &str) -> Result<u64, KernelError> {
    concept
        .constraints
        .get(name)
        .and_then(serde_norway::Value::as_u64)
        .ok_or(KernelError::Bundle)
}

fn constraint_usize(concept: &ConceptConfig, name: &str) -> Result<usize, KernelError> {
    usize::try_from(constraint_u64(concept, name)?).map_err(|_| KernelError::Bundle)
}

fn constraint_bool(concept: &ConceptConfig, name: &str) -> Result<bool, KernelError> {
    concept
        .constraints
        .get(name)
        .and_then(serde_norway::Value::as_bool)
        .ok_or(KernelError::Bundle)
}

fn has_exact_json_keys(object: &JsonMap<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn valid_code(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

trait ExactlyOne: Iterator + Sized {
    fn exactly_one(mut self) -> Option<Self::Item> {
        let item = self.next()?;
        self.next().is_none().then_some(item)
    }
}

impl<I: Iterator> ExactlyOne for I {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
    use serde_json::json;
    use tempfile::TempDir;

    use crate::signing::{jwks_document, EvidenceSigner};
    use crate::source::project_fixture_response;
    use crate::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const AUDIENCE: &str = "urn:example:fixture:audience";
    const SUPPORTED_VALUE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const SUPPORTED_VALUE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

    fn projection() -> ValueProjection<'static> {
        ValueProjection {
            audience: AUDIENCE,
            binding_key: KEY,
            binding_key_version: 1,
        }
    }

    #[test]
    fn all_four_acceptance_bundles_use_the_same_kernel() {
        let cases = [
            "adult-status",
            "residence-region",
            "professional-licence",
            "legal-parent-relationship",
        ];
        for case in cases {
            let copied = immutable_fixture(case);
            let bundle = Arc::new(Bundle::load(copied.path()).expect("acceptance bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let requirement = &bundle.config.requirements[0];
            let fixture: Value = serde_norway::from_slice(
                bundle
                    .artifact(
                        requirement
                            .fixtures
                            .as_ref()
                            .expect("acceptance fixture is declared")
                            .as_str(),
                    )
                    .expect("fixture is captured"),
            )
            .expect("fixture parses");
            let source_config = bundle
                .config
                .sources
                .get(&requirement.source)
                .expect("requirement source exists");
            for test_case in fixture["cases"].as_array().expect("cases is an array") {
                if test_case.get("source_failure").is_some()
                    || test_case.get("injected_derivation").is_some()
                    || test_case.get("companion_bundle").is_some()
                    || test_case.get("subjects").is_some()
                {
                    continue;
                }
                let Some(source) = test_case.get("source") else {
                    continue;
                };
                let source = project_fixture_response(source_config, source)
                    .map_err(|_| KernelError::SourceProtocol);
                let observed = observed_for_case(&fixture, test_case);
                let selectors = test_case
                    .get("derivationSelectorInputs")
                    .or_else(|| {
                        fixture
                            .get("common")
                            .and_then(|common| common.get("derivationSelectorInputs"))
                    })
                    .cloned()
                    .unwrap_or_else(|| Value::Object(JsonMap::new()));
                let result = source.and_then(|source| {
                    kernel.evaluate_with_selectors(
                        &requirement.id,
                        &source,
                        &selectors,
                        observed,
                        projection(),
                    )
                });
                match test_case.get("expected_lookup").and_then(Value::as_str) {
                    Some("no_match") => assert!(matches!(result, Ok(KernelOutcome::NoMatch))),
                    Some("ambiguous") => assert!(matches!(result, Ok(KernelOutcome::Ambiguous))),
                    _ if test_case.get("expected_public_problem").is_some() => {
                        assert!(result.is_err(), "{case}: {}", test_case["id"])
                    }
                    _ => {
                        let KernelOutcome::Match(values) = result.unwrap_or_else(|error| {
                            panic!("{case}: {} failed: {error:?}", test_case["id"])
                        }) else {
                            panic!("{case}: expected match");
                        };
                        assert!(!values.as_slice().is_empty());
                        if let Some(expected) = test_case.get("expected_value") {
                            assert_eq!(
                                serde_json::to_value(&values.as_slice()[0].value)
                                    .expect("value serializes"),
                                *expected
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_projected_response_outside_its_declared_shape_fails_before_extraction() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];

        // The declared response shape is the extraction contract. Rust refuses
        // a response the script would otherwise have to re-check by hand, and
        // the refusal is the same closed source-protocol class the script
        // would have raised.
        for response in [
            json!({}),
            json!({"total": "1"}),
            json!({"total": -1}),
            json!({"total": 1, "unexpected": true}),
            json!({"total": 1, "date_of_birth": 19700101}),
            json!({"total": 1, "date_of_birth": "1970-13-01"}),
        ] {
            assert_eq!(
                kernel.extract(&requirement.id, &response),
                Err(KernelError::SourceProtocol),
                "{response}"
            );
        }

        // An absent optional leaf is legitimate after projection, so it stays a
        // script decision rather than a shape violation.
        assert_eq!(
            kernel.extract(&requirement.id, &json!({"total": 1})),
            Err(KernelError::Extraction)
        );
        assert_eq!(
            kernel.extract(
                &requirement.id,
                &json!({"total": 1, "date_of_birth": "1970-01-01"})
            ),
            Ok(LookupResult::Match(BTreeMap::from([(
                "date_of_birth".to_owned(),
                json!("1970-01-01")
            )])))
        );
    }

    /// A shape rejection reaches the requester as `dependency_unavailable`,
    /// which names the provider. When the real defect is a bundle schema that
    /// no longer describes the source, the operator log is the only place that
    /// can say so, and it can only say it by naming the member and the rule.
    /// It must do that without recording any part of the response.
    #[test]
    fn a_response_shape_rejection_names_the_member_and_the_rule_but_no_value() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let requirement = &bundle.config.requirements[0];
        let source = bundle
            .config
            .sources
            .get(&requirement.source)
            .expect("the requirement names a configured source");
        let schema = bundle
            .fact_schema(&source.response_schema)
            .expect("the response schema is a bundle artifact");
        let compiled = compile_schema(schema).expect("the response schema compiles");

        let canary = "0451-mrs-hunt-was-born-in-caracas";
        let response = json!({"total": 1, "date_of_birth": canary});
        let errors = compiled
            .validate(&response)
            .expect_err("a malformed date violates the shape");
        let (violations, total) = describe_response_shape_rejection(errors);
        assert_eq!(total, 1);
        assert_eq!(
            violations,
            vec!["/date_of_birth violates /properties/date_of_birth/format".to_owned()]
        );

        // The library's own message would carry the value here, which is the
        // reason the description is built from the two pointers instead.
        assert!(
            !violations
                .iter()
                .any(|violation| violation.contains(canary)),
            "no response value reaches the log: {violations:?}"
        );

        // A violation at the document root still names somewhere.
        let not_an_object = json!([]);
        let errors = compiled
            .validate(&not_an_object)
            .expect_err("an array is not the declared object");
        let (violations, _) = describe_response_shape_rejection(errors);
        assert_eq!(
            violations,
            vec!["the response root violates /type".to_owned()]
        );

        // A source cannot decide how much the log holds.
        let many = json!({"total": -1, "date_of_birth": "not-a-date", "extra": 1});
        let errors = compiled
            .validate(&many)
            .expect_err("several rules are violated at once");
        let (violations, total) = describe_response_shape_rejection(errors);
        assert!(total >= 3, "the count is the whole number of violations");
        assert!(violations.len() <= REPORTED_SHAPE_VIOLATIONS);
    }

    #[test]
    fn extraction_failures_and_invalid_outputs_fail_closed() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        assert_eq!(
            kernel.extract(&requirement.id, &json!({"total": 0})),
            Ok(LookupResult::NoMatch)
        );
        assert_eq!(
            kernel.extract(&requirement.id, &json!({"total": 2})),
            Ok(LookupResult::Ambiguous)
        );
        assert!(kernel
            .validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: requirement.concepts[0].id.clone(),
                    value: DerivedValue::Json(json!("true")),
                }],
                projection(),
            )
            .is_err());
        let validated = kernel
            .validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: requirement.concepts[0].id.clone(),
                    value: DerivedValue::Json(json!(true)),
                }],
                projection(),
            )
            .expect("valid output");
        let debug = format!("{validated:?}");
        assert!(!debug.contains("true"));
        assert!(kernel
            .validate_values(
                &requirement.id,
                vec![
                    DerivedConceptValue {
                        concept_id: requirement.concepts[0].id.clone(),
                        value: DerivedValue::Json(json!(true)),
                    },
                    DerivedConceptValue {
                        concept_id: requirement.concepts[0].id.clone(),
                        value: DerivedValue::Json(json!(false)),
                    },
                ],
                projection(),
            )
            .is_err());
        assert!(kernel
            .validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: "urn:example:fixture:concept:extra".to_owned(),
                    value: DerivedValue::Json(json!(true)),
                }],
                projection(),
            )
            .is_err());
    }

    #[test]
    fn required_unmapped_source_fact_is_unavailable_not_a_script_failure() {
        let copied = immutable_fixture("residence-region");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let observed = "2026-08-02T00:00:00Z".parse().expect("time");
        let LookupResult::Match(facts) = kernel
            .extract(
                &requirement.id,
                &json!({"total": 1, "official_residence_code": "R-999"}),
            )
            .expect("source extracts")
        else {
            panic!("source must uniquely match");
        };
        let raw = kernel.runtime.derive(
            kernel
                .derivations
                .get(&requirement.id)
                .expect("derivation exists"),
            &facts,
            &Value::Object(JsonMap::new()),
            kernel
                .evaluation_context(requirement, observed)
                .expect("context builds"),
        );
        assert!(
            matches!(raw, Err(RhaiRuntimeError::Unavailable)),
            "unexpected closed error class: {:?}",
            raw.err()
        );
        assert_eq!(
            kernel.evaluate(
                &requirement.id,
                &json!({"total": 1, "official_residence_code": "R-999"}),
                observed,
                projection(),
            ),
            Err(KernelError::Extraction)
        );
    }

    #[test]
    fn scalar_decimal_and_collection_forms_are_exact() {
        let code_list = Codelist::Codes {
            id: "urn:example:codes".to_owned(),
            version: "1".to_owned(),
            codes: vec!["A".to_owned(), "B".to_owned()],
        };
        let codelists = BTreeMap::from([("urn:example:codes".to_owned(), code_list)]);
        let schemas = BTreeMap::new();

        assert_eq!(
            validate_value(
                &concept("form: boolean\nrequired: true\nconstraints: {}"),
                &DerivedValue::Json(json!(false)),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::Boolean(false))
        );
        assert_eq!(
            validate_value(
                &concept(
                    "form: bounded-integer\nrequired: true\nconstraints: {minimum: -2, maximum: 2}"
                ),
                &DerivedValue::Json(json!(2)),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::Integer(2))
        );
        assert_eq!(
            validate_value(
                &concept("form: controlled-code\nrequired: true\nconstraints: {codelist: 'urn:example:codes', codelistVersion: '1', maximumBytes: 8}"),
                &DerivedValue::Json(json!("A")),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::String("A".to_owned()))
        );
        assert_eq!(
            validate_value(
                &concept("form: bounded-decimal\nrequired: true\nconstraints: {minimum: '-1.5', maximum: '1.5', maximumScale: 2}"),
                &DerivedValue::Decimal(Decimal::parse("0.25").expect("decimal")),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::String("0.25".to_owned()))
        );
        assert!(validate_value(
            &concept("form: bounded-decimal\nrequired: true\nconstraints: {minimum: '-1.5', maximum: '1.5', maximumScale: 2}"),
            &DerivedValue::Json(json!(0.25)),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_err());

        let controlled = concept(
            "form: controlled-code-list\nrequired: true\nconstraints: {codelist: 'urn:example:codes', codelistVersion: '1', minimumItems: 1, maximumItems: 2, unique: true}",
        );
        assert!(validate_value(
            &controlled,
            &DerivedValue::Json(json!(["A", "A"])),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_err());
        assert!(validate_value(
            &controlled,
            &DerivedValue::Json(json!(["UNKNOWN"])),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_err());

        let category_list = Codelist::Codes {
            id: "urn:example:category-scheme".to_owned(),
            version: "7".to_owned(),
            codes: vec!["category-a".to_owned()],
        };
        let category_lists =
            BTreeMap::from([("codelists/categories.yaml".to_owned(), category_list)]);
        assert_eq!(
            validate_value(
                &concept("form: controlled-category\nrequired: true\nconstraints: {categoryScheme: 'urn:example:category-scheme', schemeVersion: '7', maximumBytes: 32, codelist: 'codelists/categories.yaml'}"),
                &DerivedValue::Json(json!("category-a")),
                &projection(),
                &category_lists,
                &schemas,
            ),
            Ok(PublicValue::String("category-a".to_owned()))
        );
    }

    #[test]
    fn bucket_entity_and_structured_forms_are_closed() {
        let buckets = Codelist::Codes {
            id: "urn:example:bucket-scheme".to_owned(),
            version: "1".to_owned(),
            codes: vec!["inside".to_owned()],
        };
        let codelists = BTreeMap::from([("buckets".to_owned(), buckets)]);
        let bucket = concept(
            "form: time-bucket\nrequired: true\nconstraints: {bucketScheme: 'urn:example:bucket-scheme', schemeVersion: '1'}",
        );
        let date_bucket = concept(
            "form: date-bucket\nrequired: true\nconstraints: {bucketScheme: 'urn:example:bucket-scheme', schemeVersion: '1'}",
        );
        assert!(matches!(
            validate_value(
                &date_bucket,
                &DerivedValue::Json(
                    json!({"form":"date-bucket","scheme":"urn:example:bucket-scheme","bucket":"inside"})
                ),
                &projection(),
                &codelists,
                &BTreeMap::new(),
            ),
            Ok(PublicValue::Bucket(BucketValue {
                form: BucketForm::DateBucket,
                ..
            }))
        ));
        assert!(validate_value(
            &bucket,
            &DerivedValue::Json(json!({"form":"time-bucket","scheme":"urn:example:bucket-scheme","bucket":"unknown"})),
            &projection(),
            &codelists,
            &BTreeMap::new(),
        )
        .is_err());

        let entity = concept(
            "form: audience-scoped-entity-reference\nrequired: true\nconstraints: {maximumBytes: 160}",
        );
        let seed = crate::values::EntityReferenceSeed::new("protected-seed").expect("seed");
        let public = validate_value(
            &entity,
            &DerivedValue::EntityReferenceSeed(seed),
            &projection(),
            &codelists,
            &BTreeMap::new(),
        )
        .expect("entity projects");
        assert!(matches!(public, PublicValue::EntityReference(_)));
        assert!(validate_value(
            &entity,
            &DerivedValue::Json(json!("protected-seed")),
            &projection(),
            &codelists,
            &BTreeMap::new(),
        )
        .is_err());

        let entity_list = concept(
            "form: entity-reference-list\nrequired: true\nconstraints: {minimumItems: 1, maximumItems: 2, unique: true}",
        );
        let duplicate = crate::values::EntityReferenceSeed::new("same-seed").expect("seed");
        assert!(validate_value(
            &entity_list,
            &DerivedValue::EntityReferenceSeedList(vec![duplicate.clone(), duplicate]),
            &projection(),
            &codelists,
            &BTreeMap::new(),
        )
        .is_err());
        let projected = validate_value(
            &entity_list,
            &DerivedValue::EntityReferenceSeedList(vec![
                crate::values::EntityReferenceSeed::new("seed-a").expect("seed"),
                crate::values::EntityReferenceSeed::new("seed-b").expect("seed"),
            ]),
            &projection(),
            &codelists,
            &BTreeMap::new(),
        )
        .expect("entity list projects");
        assert!(matches!(projected, PublicValue::List(_)));

        let schema_id = "urn:example:structured";
        let schema = compile_schema(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": schema_id,
            "type": "object",
            "additionalProperties": false,
            "required": ["status", "effective_date", "observed_at"],
            "properties": {
                "status": {"type": "string", "enum": ["A"]},
                "effective_date": {"type": "string", "format": "date"},
                "observed_at": {"type": "string", "format": "date-time"}
            }
        }))
        .expect("schema compiles");
        let schemas = BTreeMap::from([(schema_id.to_owned(), schema)]);
        let structured = concept(
            "form: reviewed-structured-value\nrequired: true\nconstraints: {schema: 'urn:example:structured', maximumSerializedBytes: 512}",
        );
        assert!(validate_value(
            &structured,
            &DerivedValue::Json(json!({"form":"reviewed-structured-value","schema":schema_id,"fields":{"status":"A","effective_date":"2026-02-30","observed_at":"not-an-instant"}})),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_err());
        assert!(validate_value(
            &structured,
            &DerivedValue::Json(json!({"form":"reviewed-structured-value","schema":schema_id,"fields":{"status":"A","effective_date":"2026-02-28","observed_at":"2026-02-28T12:00:00Z"}})),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_ok());
    }

    #[test]
    fn evidence_construction_is_deterministic_and_role_ordered() {
        let copied = immutable_fixture("legal-parent-relationship");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let values = kernel
            .validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: requirement.concepts[0].id.clone(),
                    value: DerivedValue::Json(json!(false)),
                }],
                projection(),
            )
            .expect("values validate");
        let construction = || EvidenceConstruction {
            evidence_id: "urn:ulid:01K1EXAMPLE0000000000000000",
            request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
            purpose: &requirement.purposes[0],
            audience: AUDIENCE,
            issued_at: "2026-08-02T00:00:01Z".parse().expect("time"),
            observed_at: "2026-08-02T00:00:00Z".parse().expect("time"),
            subjects: vec![
                SubjectBinding {
                    role: "child".to_owned(),
                    binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
                },
                SubjectBinding {
                    role: "candidate-parent".to_owned(),
                    binding: format!("urn:evidence:subject:v1_{}", "B".repeat(43)),
                },
            ],
        };
        let first = kernel
            .construct_evidence(&requirement.id, values.clone(), construction())
            .expect("constructs");
        let second = kernel
            .construct_evidence(&requirement.id, values, construction())
            .expect("constructs");
        assert_eq!(first, second);
        assert_eq!(first.supported_values[0].value, PublicValue::Boolean(false));
        assert_eq!(first.subjects[0].role, "child");
        assert_eq!(first.subjects[1].role, "candidate-parent");
        assert_eq!(first.valid_until, "2026-08-02T00:05:01Z");
    }

    #[tokio::test]
    async fn supported_value_fixture_cases_use_the_real_gate_and_signed_round_trip() {
        let fixture = supported_values_fixture();
        assert_eq!(
            fixture["fixture"].as_str(),
            Some("registry.evidence.supported-values/v1")
        );
        assert_eq!(fixture["synthetic_only"].as_bool(), Some(true));

        let copied = immutable_supported_values_bundle();
        let bundle = Arc::new(Bundle::load(copied.path()).expect("supported-value bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let forms = fixture["forms"].as_array().expect("forms are an array");
        assert_eq!(forms.len(), 11, "all Version 1 forms remain covered");
        assert_eq!(requirement.concepts.len(), forms.len());

        let signer = supported_values_signer().await;
        for form_fixture in forms {
            let form = form_fixture["form"].as_str().expect("form name");
            let concept_id = format!("urn:example:fixture:concept:{form}");
            let concept = requirement
                .concepts
                .iter()
                .find(|candidate| candidate.id == concept_id)
                .unwrap_or_else(|| panic!("bundle declaration missing {form}"));
            assert_fixture_declaration(form_fixture, concept);

            for category in ["positive", "boundary"] {
                let cases = form_fixture[category]
                    .as_array()
                    .unwrap_or_else(|| panic!("{form} {category} cases"));
                for (index, fixture_case) in cases.iter().enumerate() {
                    let derived = accepted_derived_value(
                        &kernel,
                        requirement,
                        form_fixture,
                        category,
                        index,
                        fixture_case,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{form} {category}[{index}] derivation failed: {error:?}")
                    });
                    let values = gate_fixture_value(&kernel, requirement, form, derived)
                        .unwrap_or_else(|error| {
                            panic!("{form} {category}[{index}] gate failed: {error:?}")
                        });
                    let public = values
                        .as_slice()
                        .iter()
                        .find(|value| value.provides_value_for == concept_id)
                        .unwrap_or_else(|| panic!("{form} value was not emitted"));
                    assert_fixture_public_shape(form, fixture_case, &public.value);
                    assert_signed_type_preserving_round_trip(&kernel, requirement, values, &signer)
                        .await;
                }
            }

            let negatives = form_fixture["negative"]
                .as_array()
                .unwrap_or_else(|| panic!("{form} negatives"));
            for (index, fixture_case) in negatives.iter().enumerate() {
                let derivation =
                    fixture_derived_value(&kernel, requirement, &concept_id, fixture_case);
                if fixture_case.get("leak_surface").is_some() {
                    let derived = derivation.unwrap_or_else(|error| {
                        panic!("{form} privacy negative[{index}] must derive: {error:?}")
                    });
                    let values = gate_fixture_value(&kernel, requirement, form, derived)
                        .expect("protected seed is projected by the output gate");
                    let serialized = serde_json::to_string(values.as_slice()).expect("serializes");
                    let debug = format!("{values:?}");
                    assert!(!serialized.contains("source-seed-canary"));
                    assert!(!debug.contains("source-seed-canary"));
                } else {
                    let rejected = match derivation {
                        Err(_) => true,
                        Ok(derived) => {
                            gate_fixture_value(&kernel, requirement, form, derived).is_err()
                        }
                    };
                    assert!(rejected, "{form} negative[{index}] must fail closed");
                }
            }
        }
    }

    #[test]
    fn supported_value_fixture_global_negatives_are_enforced() {
        let fixture = supported_values_fixture();
        let declared = fixture["global_negative"]
            .as_array()
            .expect("global negatives")
            .iter()
            .map(|value| value.as_str().expect("negative id"))
            .collect::<Vec<_>>();
        assert_eq!(
            declared,
            vec![
                "undeclared-concept",
                "duplicate-concept",
                "missing-required-concept",
                "extra-value-metadata",
                "per-value-size-plus-one",
                "aggregate-result-size-plus-one",
            ]
        );

        let copied = immutable_supported_values_bundle();
        let bundle = Arc::new(Bundle::load(copied.path()).expect("supported-value bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let boolean = || DerivedConceptValue {
            concept_id: "urn:example:fixture:concept:boolean".to_owned(),
            value: DerivedValue::Json(json!(true)),
        };

        assert_eq!(
            kernel.validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: "urn:example:fixture:concept:undeclared".to_owned(),
                    value: DerivedValue::Json(json!(true)),
                }],
                projection(),
            ),
            Err(KernelError::Output),
            "undeclared-concept"
        );
        assert_eq!(
            kernel.validate_values(&requirement.id, vec![boolean(), boolean()], projection(),),
            Err(KernelError::Output),
            "duplicate-concept"
        );
        assert_eq!(
            kernel.validate_values(
                &requirement.id,
                vec![DerivedConceptValue {
                    concept_id: "urn:example:fixture:concept:bounded-integer".to_owned(),
                    value: DerivedValue::Json(json!(0)),
                }],
                projection(),
            ),
            Err(KernelError::Output),
            "missing-required-concept"
        );

        let extra_metadata = r#"
            fn derive(facts, selectors, evaluation_context) {
                [#{
                    concept_id: "urn:example:fixture:concept:boolean",
                    value: true,
                    confidence: "not-allowed"
                }]
            }
        "#;
        let script = kernel
            .runtime
            .compile_derivation(extra_metadata)
            .expect("negative script compiles");
        assert!(
            kernel
                .runtime
                .derive(
                    &script,
                    &BTreeMap::new(),
                    &Value::Object(JsonMap::new()),
                    kernel
                        .evaluation_context(
                            requirement,
                            "2026-08-02T00:00:00Z".parse().expect("time")
                        )
                        .expect("context"),
                )
                .is_err(),
            "extra-value-metadata"
        );

        let oversized = "A".repeat(MAXIMUM_PUBLIC_STRING_BYTES + 1);
        let oversized_codelist = Codelist::Codes {
            id: "urn:example:fixture:codelist:oversized".to_owned(),
            version: "1".to_owned(),
            codes: vec![oversized.clone()],
        };
        assert_eq!(
            validate_value(
                &concept("form: controlled-code\nrequired: true\nconstraints: {codelist: oversized, codelistVersion: '1', maximumBytes: 8192}"),
                &DerivedValue::Json(Value::String(oversized)),
                &projection(),
                &BTreeMap::from([("oversized".to_owned(), oversized_codelist)]),
                &BTreeMap::new(),
            ),
            Err(KernelError::Output),
            "per-value-size-plus-one"
        );

        let aggregate_schema_id = "urn:example:fixture:schema:aggregate:v1";
        let aggregate_schema = compile_schema(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": aggregate_schema_id,
            "type": "object",
            "additionalProperties": false,
            "required": ["blob"],
            "properties": {"blob": {"type": "string", "maxLength": 5000}}
        }))
        .expect("aggregate schema compiles");
        let aggregate_concepts = (0..16)
            .map(|index| {
                let mut candidate = concept(&format!(
                    "form: reviewed-structured-value\nrequired: false\nconstraints: {{schema: '{aggregate_schema_id}', maximumSerializedBytes: 8192}}"
                ));
                candidate.id = format!("urn:example:fixture:concept:aggregate-{index}");
                candidate
            })
            .collect::<Vec<_>>();
        let mut aggregate_requirement = requirement.clone();
        aggregate_requirement.concepts = aggregate_concepts;
        let aggregate_values = (0..16)
            .map(|index| DerivedConceptValue {
                concept_id: format!("urn:example:fixture:concept:aggregate-{index}"),
                value: DerivedValue::Json(json!({
                    "form": "reviewed-structured-value",
                    "schema": aggregate_schema_id,
                    "fields": {"blob": "X".repeat(4200)}
                })),
            })
            .collect();
        assert_eq!(
            gate_values(
                &aggregate_requirement,
                aggregate_values,
                projection(),
                &BTreeMap::new(),
                &BTreeMap::from([(aggregate_schema_id.to_owned(), aggregate_schema)]),
            ),
            Err(KernelError::Output),
            "aggregate-result-size-plus-one"
        );
    }

    fn supported_values_fixture() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/conformance/supported-values.yaml");
        serde_norway::from_slice(&fs::read(path).expect("supported-value fixture reads"))
            .expect("supported-value fixture parses")
    }

    fn supported_values_bundle_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/conformance/supported-values")
    }

    fn immutable_supported_values_bundle() -> TempDir {
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_tree(&supported_values_bundle_path(), temporary.path());
        make_read_only(temporary.path());
        temporary
    }

    fn gate_fixture_value(
        kernel: &OfflineKernel,
        requirement: &RequirementConfig,
        form: &str,
        derived: DerivedConceptValue,
    ) -> Result<ValidatedValues, KernelError> {
        let mut values = Vec::with_capacity(2);
        if form != "boolean" {
            values.push(DerivedConceptValue {
                concept_id: "urn:example:fixture:concept:boolean".to_owned(),
                value: DerivedValue::Json(json!(true)),
            });
        }
        values.push(derived);
        kernel.validate_values(&requirement.id, values, projection())
    }

    fn assert_fixture_declaration(form_fixture: &Value, concept: &ConceptConfig) {
        let form = form_fixture["form"].as_str().expect("form");
        let declaration = form_fixture["declaration"]
            .as_object()
            .expect("form declaration");
        assert_eq!(declaration["form"], form);
        assert_eq!(
            serde_json::to_value(concept.form).expect("form serializes"),
            Value::String(form.to_owned())
        );
        assert_eq!(
            concept.required,
            declaration
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        );

        let mut expected = JsonMap::new();
        for (name, value) in declaration {
            let translated = match name.as_str() {
                "form" | "required" | "fields" => continue,
                "codelist" => "codelist",
                "codelist_version" => "codelistVersion",
                "category_scheme" => "categoryScheme",
                "scheme_version" => "schemeVersion",
                "maximum_bytes" => "maximumBytes",
                "maximum_scale" => "maximumScale",
                "bucket_scheme" => "bucketScheme",
                "minimum_items" => "minimumItems",
                "maximum_items" => "maximumItems",
                "maximum_serialized_bytes" => "maximumSerializedBytes",
                other => other,
            };
            let value = if name == "codelist" && value.as_str() == Some("synthetic-codes") {
                Value::String("codelists/synthetic-codes.yaml".to_owned())
            } else {
                value.clone()
            };
            expected.insert(translated.to_owned(), value);
        }
        if form == "controlled-category" {
            expected.insert(
                "codelist".to_owned(),
                Value::String("codelists/categories.yaml".to_owned()),
            );
        }
        assert_eq!(
            serde_json::to_value(&concept.constraints).expect("constraints serialize"),
            Value::Object(expected),
            "{form} fixture declaration must be the executable bundle declaration"
        );
    }

    fn accepted_derived_value(
        kernel: &OfflineKernel,
        requirement: &RequirementConfig,
        form_fixture: &Value,
        category: &str,
        index: usize,
        fixture_case: &Value,
    ) -> Result<DerivedConceptValue, RhaiRuntimeError> {
        let form = form_fixture["form"].as_str().expect("form");
        let concept_id = format!("urn:example:fixture:concept:{form}");
        if form == "audience-scoped-entity-reference" {
            let expression = if category == "positive" {
                form_fixture["derivation_positive"][index]["rhai"]
                    .as_str()
                    .expect("entity derivation")
                    .to_owned()
            } else {
                "entity_reference_seed(\"synthetic-boundary-seed\")".to_owned()
            };
            return derive_expression(kernel, requirement, &concept_id, &expression);
        }
        if form == "entity-reference-list" {
            let derivation_index = if category == "positive" {
                index
            } else {
                index + 1
            };
            let expressions = form_fixture["derivation_positive"][derivation_index]
                .as_array()
                .expect("entity list derivation")
                .iter()
                .map(|value| value.as_str().expect("Rhai expression"))
                .collect::<Vec<_>>()
                .join(", ");
            return derive_expression(
                kernel,
                requirement,
                &concept_id,
                &format!("[{expressions}]"),
            );
        }
        fixture_derived_value(kernel, requirement, &concept_id, fixture_case)
    }

    fn fixture_derived_value(
        kernel: &OfflineKernel,
        requirement: &RequirementConfig,
        concept_id: &str,
        fixture_case: &Value,
    ) -> Result<DerivedConceptValue, RhaiRuntimeError> {
        if let Some(expression) = fixture_case.get("rhai") {
            let expression = match expression {
                Value::Array(expressions) => format!(
                    "[{}]",
                    expressions
                        .iter()
                        .map(rhai_fixture_expression)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                value => rhai_fixture_expression(value),
            };
            derive_expression(kernel, requirement, concept_id, &expression)
        } else {
            Ok(DerivedConceptValue {
                concept_id: concept_id.to_owned(),
                value: DerivedValue::Json(fixture_case.clone()),
            })
        }
    }

    fn rhai_fixture_expression(value: &Value) -> String {
        match value {
            Value::String(value)
                if value.starts_with("decimal(")
                    || value.starts_with("parse_decimal(")
                    || value.starts_with("entity_reference_seed(") =>
            {
                value.clone()
            }
            Value::String(value) => serde_json::to_string(value).expect("string expression"),
            Value::Number(value) => value.to_string(),
            _ => panic!("unsupported fixture Rhai expression form"),
        }
    }

    fn derive_expression(
        kernel: &OfflineKernel,
        requirement: &RequirementConfig,
        concept_id: &str,
        expression: &str,
    ) -> Result<DerivedConceptValue, RhaiRuntimeError> {
        let source = format!(
            "fn derive(facts, selectors, evaluation_context) {{ [#{{ concept_id: \"{concept_id}\", value: {expression} }}] }}"
        );
        let script = kernel.runtime.compile_derivation(&source)?;
        let values = kernel.runtime.derive(
            &script,
            &BTreeMap::new(),
            &Value::Object(JsonMap::new()),
            kernel
                .evaluation_context(requirement, "2026-08-02T00:00:00Z".parse().expect("time"))
                .expect("evaluation context"),
        )?;
        values
            .into_iter()
            .next()
            .ok_or(RhaiRuntimeError::DerivationResult)
    }

    fn assert_fixture_public_shape(form: &str, fixture_case: &Value, actual: &PublicValue) {
        let actual = serde_json::to_value(actual).expect("public value serializes");
        if let Some(wire) = fixture_case.get("wire_json").and_then(Value::as_str) {
            let expected: Value = serde_json::from_str(wire).expect("wire JSON parses");
            assert_eq!(actual, expected);
            return;
        }
        match form {
            "audience-scoped-entity-reference" => {
                let _: PublicValue = serde_json::from_value(fixture_case.clone())
                    .expect("public entity exemplar parses");
                assert_eq!(actual["form"], "audience-scoped-entity-reference");
                let reference = actual["reference"].as_str().expect("projected reference");
                assert!(reference.starts_with("urn:evidence:entity:v1_"));
            }
            "entity-reference-list" => {
                let _: PublicValue = serde_json::from_value(fixture_case.clone())
                    .expect("public entity-list exemplar parses");
                assert_eq!(
                    actual.as_array().map(Vec::len),
                    fixture_case.as_array().map(Vec::len)
                );
                assert!(actual
                    .as_array()
                    .expect("public list")
                    .iter()
                    .all(|item| item["form"] == "audience-scoped-entity-reference"));
            }
            _ => assert_eq!(actual, *fixture_case),
        }
    }

    async fn supported_values_signer() -> EvidenceSigner {
        let private = PrivateJwk::parse(SUPPORTED_VALUE_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));
        EvidenceSigner::initialize(provider, SUPPORTED_VALUE_KEY_ID)
            .await
            .expect("fixture signer initializes")
    }

    async fn assert_signed_type_preserving_round_trip(
        kernel: &OfflineKernel,
        requirement: &RequirementConfig,
        values: ValidatedValues,
        signer: &EvidenceSigner,
    ) {
        let evidence = kernel
            .construct_evidence(
                &requirement.id,
                values,
                EvidenceConstruction {
                    evidence_id: "urn:ulid:01K1SUPPORTEDVALUES0000000000",
                    request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                    purpose: "conformance",
                    audience: AUDIENCE,
                    issued_at: "2026-08-02T00:00:01Z".parse().expect("time"),
                    observed_at: "2026-08-02T00:00:00Z".parse().expect("time"),
                    subjects: vec![SubjectBinding {
                        role: "subject".to_owned(),
                        binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
                    }],
                },
            )
            .expect("Evidence constructs");
        let expected_values =
            serde_json::to_value(&evidence.supported_values).expect("values serialize");
        let jws = signer
            .sign_json(&evidence)
            .await
            .expect("fixture Evidence signs");
        let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("fixture JWKS builds");
        let verified = verify_flattened_jws(
            &serialized,
            &jwks,
            &EvidenceVerificationPolicy::from_accepted_transaction(
                &evidence,
                &evidence.request_nonce,
                48 * 60 * 60,
                "2026-08-02T00:03:00Z".parse().expect("time"),
                30,
            )
            .expect("the fixture policy states bounds the contract allows"),
        )
        .expect("signed Evidence verifies");
        assert_eq!(
            serde_json::to_value(verified.supported_values).expect("verified values serialize"),
            expected_values,
            "JSON value types must survive construction, signing, verification, and parsing"
        );
    }

    fn concept(body: &str) -> ConceptConfig {
        serde_norway::from_str(&format!("id: urn:example:concept\n{body}\n"))
            .expect("concept parses")
    }

    fn observed_for_case(fixture: &Value, test_case: &Value) -> DateTime<Utc> {
        let local_date = test_case
            .get("legal_local_date")
            .or_else(|| {
                fixture
                    .get("common")
                    .and_then(|common| common.get("legal_local_date"))
            })
            .and_then(Value::as_str)
            .unwrap_or("2026-08-02");
        format!("{local_date}T00:00:00Z")
            .parse()
            .expect("observed time")
    }

    fn immutable_fixture(name: &str) -> TempDir {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(name);
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_tree(&source, temporary.path());
        make_read_only(temporary.path());
        temporary
    }

    fn copy_tree(source: &Path, target: &Path) {
        for entry in fs::read_dir(source).expect("reads fixture") {
            let entry = entry.expect("directory entry");
            let destination = target.join(entry.file_name());
            if entry.file_type().expect("file type").is_dir() {
                fs::create_dir(&destination).expect("creates directory");
                copy_tree(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).expect("copies fixture");
            }
        }
    }

    #[cfg(unix)]
    fn make_read_only(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        for entry in fs::read_dir(path).expect("reads copied fixture") {
            let entry = entry.expect("directory entry");
            let child = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                make_read_only(&child);
                fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                    .expect("locks directory");
            } else {
                fs::set_permissions(&child, fs::Permissions::from_mode(0o444)).expect("locks file");
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o555)).expect("locks root");
    }

    #[cfg(not(unix))]
    fn make_read_only(path: &Path) {
        for entry in fs::read_dir(path).expect("reads copied fixture") {
            let entry = entry.expect("directory entry");
            let child = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                make_read_only(&child);
            } else {
                let mut permissions = fs::metadata(&child).expect("metadata").permissions();
                permissions.set_readonly(true);
                fs::set_permissions(child, permissions).expect("locks file");
            }
        }
    }
}
