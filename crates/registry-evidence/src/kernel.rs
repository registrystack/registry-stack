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
use crate::bundle::{ArtifactFault, Bundle, Codelist};
use crate::config::{
    ConceptConfig, ConceptForm, PreparationChannelPolicy, PreparationLimits, RequirementConfig,
    SchemaFault, SourceConfig, SourceSelectorSet, SqlitePreparationLimits,
};
use crate::model::{
    BucketForm, BucketValue, EntityReferenceForm, EntityReferenceValue, Evidence,
    EvidenceObjectType, LookupResult, PublicValue, ScalarOrEntityReference, StructuredValue,
    StructuredValueForm, SubjectBinding, SubjectBindingMode, SupportedValue,
};
use crate::rhai_runtime::{
    CalendarDate, CodelistHandle, CompiledBatchExtraction, CompiledBatchPreparation,
    CompiledDerivation, CompiledExtraction, CompiledPreparation, DerivedConceptValue, DerivedValue,
    EvaluationContext, LegalLocalTime, RequestPartRequirement, RequestPartsBounds,
    RequestPartsLimits, RhaiRuntime, RhaiRuntimeError, StatementParameters,
    StatementParametersLimits, UtcInstant, MAXIMUM_RESULT_BYTES,
};
use crate::source::{PreparedSourceBatchRequest, PreparedSourceRequest};
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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// A bundle invariant configuration validation already proved, or a
    /// bundle-level refusal that names no single artifact.
    #[error("the Evidence bundle cannot initialize the offline kernel")]
    Bundle,
    /// One named bundle artifact was refused while the kernel compiled it.
    ///
    /// This is the same bundle-level failure class as `Bundle` and shares its
    /// audit category and public problem. It exists so an adopter learns which
    /// reviewed file to fix, because the kernel is the first pass that reads
    /// every artifact under the hardened grammar and the full schema draft.
    ///
    /// The message stays value-free. The diagnostic it carries names a
    /// bundle-relative artifact and one static cause, and is rendered by the
    /// adopter-facing command rather than by this message.
    #[error("an Evidence bundle artifact cannot compile")]
    Artifact(ArtifactFault),
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

impl KernelError {
    /// The value-free diagnostic, when this failure names one bundle artifact.
    ///
    /// Every other variant describes an evaluation the bundle asked for rather
    /// than a file the bundle contains, so there is no artifact to name.
    pub fn artifact_fault(&self) -> Option<&ArtifactFault> {
        match self {
            Self::Artifact(fault) => Some(fault),
            _ => None,
        }
    }
}

/// Refuse one named bundle artifact with a value-free cause.
///
/// The artifact is a bundle-relative path taken from the reviewed bundle
/// layout, never from document content.
fn refuse_artifact(artifact: &str, cause: &'static str) -> KernelError {
    KernelError::Artifact(ArtifactFault::new(artifact, SchemaFault::because(cause)))
}

/// Reduce a script compilation failure to one static cause.
///
/// The engine's own message quotes script text and offsets into it, so the
/// hardened runtime discards it at its boundary and reports only this closed
/// set. Every other runtime failure belongs to an evaluation rather than to a
/// compilation, and collapses to the general cause.
fn script_compile_cause(error: RhaiRuntimeError) -> &'static str {
    match error {
        RhaiRuntimeError::EntryPoint => "script entry point is invalid",
        RhaiRuntimeError::InputBound => "script exceeds its size bound",
        _ => "script does not compile",
    }
}

/// Every failure after a physical batch response exists is global. Keeping the
/// mapping in one function prevents a malformed member or FactSet from taking
/// the ordinary per-item unavailable lane used by sequential extraction.
fn batch_extraction_failure(_: RhaiRuntimeError) -> KernelError {
    KernelError::SourceProtocol
}

#[derive(Clone, Copy)]
enum ExtractionFailurePolicy {
    /// Preserve the frozen singular and holder-bound public collapse.
    Ordinary,
    /// A malformed member aborts the atomic outer request batch.
    RequestBatch,
}

fn extraction_failure(error: RhaiRuntimeError, policy: ExtractionFailurePolicy) -> KernelError {
    match error {
        RhaiRuntimeError::Unavailable => KernelError::Extraction,
        RhaiRuntimeError::ExtractionResult | RhaiRuntimeError::FactSchema => match policy {
            ExtractionFailurePolicy::Ordinary => KernelError::Extraction,
            ExtractionFailurePolicy::RequestBatch => KernelError::SourceProtocol,
        },
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
    }
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

/// What one assertion is scoped to, and the members that scope carries.
///
/// The two members an audience-scoped assertion carries live inside the
/// variant that owns them, so a holder-bound construction cannot state an
/// audience or a request nonce at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceScope<'a> {
    AudienceScoped {
        audience: &'a str,
        /// Exact caller nonce to echo. It is copied verbatim into the payload
        /// and is not part of the subject binding, audit, or any diagnostic
        /// surface.
        request_nonce: &'a str,
    },
    HolderBound,
}

impl<'a> EvidenceScope<'a> {
    pub fn audience(self) -> Option<&'a str> {
        match self {
            Self::AudienceScoped { audience, .. } => Some(audience),
            Self::HolderBound => None,
        }
    }

    pub fn request_nonce(self) -> Option<&'a str> {
        match self {
            Self::AudienceScoped { request_nonce, .. } => Some(request_nonce),
            Self::HolderBound => None,
        }
    }

    fn mode(self) -> SubjectBindingMode {
        match self {
            Self::AudienceScoped { .. } => SubjectBindingMode::AudienceScoped,
            Self::HolderBound => SubjectBindingMode::HolderBound,
        }
    }
}

/// Runtime-owned inputs needed to project protected derivation values.
pub struct ValueProjection<'a> {
    pub scope: EvidenceScope<'a>,
    pub binding_key: &'a [u8],
    pub binding_key_version: u32,
}

/// Core-owned envelope inputs supplied by the authenticated release pipeline.
pub struct EvidenceConstruction<'a> {
    pub evidence_id: &'a str,
    pub purpose: &'a str,
    pub scope: EvidenceScope<'a>,
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

fn compile_statement_parameters_limits(
    configured: &SqlitePreparationLimits,
) -> Result<StatementParametersLimits, KernelError> {
    fn bounded(value: u64) -> Result<usize, KernelError> {
        usize::try_from(value).map_err(|_| KernelError::Bundle)
    }

    StatementParametersLimits::new(
        bounded(configured.maximum_parameters)?,
        bounded(configured.maximum_parameter_value_bytes)?,
    )
    .map_err(|_| KernelError::Bundle)
}

/// Hold the caller-visible JSON representation to the exact minimized source
/// selector grammar before it is copied into a batch script input.
fn batch_selector_items_are_exact(
    source: &SourceConfig,
    allowed_sets: &[SourceSelectorSet],
    items: &[Value],
) -> bool {
    items.iter().all(|item| {
        let Some(roles) = item.as_object() else {
            return false;
        };
        let mut active = Vec::with_capacity(roles.len());
        for (role, selector) in roles {
            let Some(input) = source
                .selector_inputs()
                .iter()
                .find(|input| input.role == *role)
            else {
                return false;
            };
            let Some(selector) = selector.as_object() else {
                return false;
            };
            if selector.len() != 2
                || !selector.contains_key("profile")
                || !selector.contains_key("values")
            {
                return false;
            }
            let Some(profile) = selector.get("profile").and_then(Value::as_str) else {
                return false;
            };
            let Some(alternative) = input
                .alternatives
                .iter()
                .find(|alternative| alternative.profile == profile)
            else {
                return false;
            };
            let Some(values) = selector.get("values").and_then(Value::as_object) else {
                return false;
            };
            let expected = alternative.fields.iter().collect::<BTreeSet<_>>();
            if values.keys().collect::<BTreeSet<_>>() != expected
                || values.values().any(|value| {
                    !matches!(value, Value::String(_) | Value::Bool(_)) && value.as_i64().is_none()
                })
            {
                return false;
            }
            active.push((role.clone(), profile.to_owned()));
        }
        active.sort();
        allowed_sets.contains(&active)
    })
}

/// A kernel compiled entirely from the bytes captured in one immutable bundle.
pub struct OfflineKernel {
    bundle: Arc<Bundle>,
    runtime: RhaiRuntime,
    preparations: BTreeMap<String, CompiledPreparation>,
    extractions: BTreeMap<String, CompiledExtraction>,
    request_parts_limits: BTreeMap<String, RequestPartsLimits>,
    statement_parameters_limits: BTreeMap<String, StatementParametersLimits>,
    batch_preparations: BTreeMap<String, CompiledBatchPreparation>,
    batch_extractions: BTreeMap<String, CompiledBatchExtraction>,
    batch_response_schemas: BTreeMap<String, JSONSchema>,
    derivations: BTreeMap<String, CompiledDerivation>,
    response_schemas: BTreeMap<String, JSONSchema>,
    fact_schemas: BTreeMap<String, JSONSchema>,
    reviewed_schemas: BTreeMap<String, JSONSchema>,
    codelist_handles: BTreeMap<String, BTreeMap<String, CodelistHandle>>,
}

/// One internally slotted, reviewed optimized source request.
///
/// The slot sequence, source identity, and adapter identity are retained with
/// the preparation so extraction cannot be invoked against another source or
/// with a caller-supplied correlation set. Its diagnostic form contains no
/// selectors or request parts.
pub struct PreparedSourceBatch {
    source_id: String,
    adapter_id: String,
    slots: Vec<i64>,
    request: PreparedSourceBatchRequest,
}

impl PreparedSourceBatch {
    pub fn request(&self) -> &PreparedSourceBatchRequest {
        &self.request
    }

    pub fn item_count(&self) -> usize {
        self.slots.len()
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }
}

impl std::fmt::Debug for PreparedSourceBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSourceBatch")
            .field("source_id", &self.source_id)
            .field("adapter_id", &self.adapter_id)
            .field("item_count", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OfflineKernel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineKernel")
            .field("bundle_revision", &self.bundle.revision())
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
        let mut statement_parameters_limits = BTreeMap::new();
        let mut batch_preparations = BTreeMap::new();
        let mut batch_extractions = BTreeMap::new();
        let mut batch_response_schemas = BTreeMap::new();
        let mut response_schemas = BTreeMap::new();
        let mut fact_schemas = BTreeMap::new();
        for (source_id, source) in bundle.config.sources.iter() {
            // Request preparation is compiled in the shape the source's own
            // transport consumes, and only where there is something to prepare.
            // A statement source without a preparation script binds every
            // parameter declaratively and gets no preparation channel at all,
            // so asking for one later fails rather than running an absent
            // script.
            match source {
                SourceConfig::HttpJson { request, .. } => {
                    let preparation = bundle
                        .script(&request.prepare_script)
                        .ok_or(KernelError::Bundle)?;
                    let compiled_preparation = runtime
                        .compile_preparation(&preparation.source)
                        .map_err(|error| {
                            refuse_artifact(
                                request.prepare_script.as_str(),
                                script_compile_cause(error),
                            )
                        })?;
                    preparations.insert(source_id.to_owned(), compiled_preparation);
                    request_parts_limits.insert(
                        source_id.to_owned(),
                        compile_request_parts_limits(&request.preparation_limits)?,
                    );
                    if let Some(batch) = source.batch() {
                        let preparation = bundle
                            .script(&batch.prepare_script)
                            .ok_or(KernelError::Bundle)?;
                        let compiled = runtime
                            .compile_batch_preparation(&preparation.source)
                            .map_err(|error| {
                                refuse_artifact(
                                    batch.prepare_script.as_str(),
                                    script_compile_cause(error),
                                )
                            })?;
                        batch_preparations.insert(source_id.to_owned(), compiled);

                        let extraction = bundle
                            .script(&batch.extract_script)
                            .ok_or(KernelError::Bundle)?;
                        let compiled = runtime
                            .compile_batch_extraction(&extraction.source)
                            .map_err(|error| {
                                refuse_artifact(
                                    batch.extract_script.as_str(),
                                    script_compile_cause(error),
                                )
                            })?;
                        batch_extractions.insert(source_id.to_owned(), compiled);

                        let schema = bundle
                            .fact_schema(&batch.response_schema)
                            .ok_or(KernelError::Bundle)?;
                        batch_response_schemas.insert(
                            source_id.to_owned(),
                            compile_schema(batch.response_schema.as_str(), schema)?,
                        );
                    }
                }
                SourceConfig::SqliteExtract { request, .. } => {
                    if let (Some(prepare_script), Some(limits)) =
                        (&request.prepare_script, &request.preparation_limits)
                    {
                        let preparation =
                            bundle.script(prepare_script).ok_or(KernelError::Bundle)?;
                        let compiled_preparation = runtime
                            .compile_preparation(&preparation.source)
                            .map_err(|error| {
                                refuse_artifact(
                                    prepare_script.as_str(),
                                    script_compile_cause(error),
                                )
                            })?;
                        preparations.insert(source_id.to_owned(), compiled_preparation);
                        statement_parameters_limits.insert(
                            source_id.to_owned(),
                            compile_statement_parameters_limits(limits)?,
                        );
                    }
                }
            }

            let extraction = bundle
                .script(source.extract_script())
                .ok_or(KernelError::Bundle)?;
            let compiled_extraction =
                runtime
                    .compile_extraction(&extraction.source)
                    .map_err(|error| {
                        refuse_artifact(
                            source.extract_script().as_str(),
                            script_compile_cause(error),
                        )
                    })?;
            extractions.insert(source_id.to_owned(), compiled_extraction);

            let response_schema = bundle
                .fact_schema(source.response_schema())
                .ok_or(KernelError::Bundle)?;
            response_schemas.insert(
                source_id.to_owned(),
                compile_schema(source.response_schema().as_str(), response_schema)?,
            );

            let schema = bundle
                .fact_schema(source.fact_schema())
                .ok_or(KernelError::Bundle)?;
            let compiled_schema = compile_schema(source.fact_schema().as_str(), schema)?;
            fact_schemas.insert(source_id.to_owned(), compiled_schema);
        }

        let mut derivations = BTreeMap::new();
        for requirement in &bundle.config.requirements {
            let script = bundle
                .script(&requirement.derivation.script)
                .ok_or(KernelError::Bundle)?;
            let compiled = runtime
                .compile_derivation(&script.source)
                .map_err(|error| {
                    refuse_artifact(
                        requirement.derivation.script.as_str(),
                        script_compile_cause(error),
                    )
                })?;
            derivations.insert(requirement.id.clone(), compiled);
        }

        let mut reviewed_schemas = BTreeMap::new();
        for (path, schema) in bundle.fact_schemas.iter() {
            if let Some(identifier) = schema.get("$id").and_then(Value::as_str) {
                if reviewed_schemas
                    .insert(identifier.to_owned(), compile_schema(path, schema)?)
                    .is_some()
                {
                    return Err(refuse_artifact(path, "schema declares a duplicate $id"));
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
            statement_parameters_limits,
            batch_preparations,
            batch_extractions,
            batch_response_schemas,
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
    ) -> Result<PreparedSourceRequest, KernelError> {
        let requirement = self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?;
        let source_id = requirement.acquisition.initial_source();
        self.prepare_source(source_id, selectors, &BTreeMap::new())
    }

    /// Run one source's reviewed preparation script with the closed adapter
    /// context. Prior facts are empty for single and search calls and contain
    /// only the schema-validated search `FactSet` for a fetch call.
    pub fn prepare_source(
        &self,
        source_id: &str,
        selectors: &Value,
        prior_facts: &BTreeMap<String, Value>,
    ) -> Result<PreparedSourceRequest, KernelError> {
        let source = self
            .bundle
            .config
            .sources
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let parameters =
            serde_json::to_value(source.adapter_parameters()).map_err(|_| KernelError::Bundle)?;
        match source {
            SourceConfig::HttpJson { .. } => {
                let script = self
                    .preparations
                    .get(source_id)
                    .ok_or(KernelError::Bundle)?;
                let limits = self
                    .request_parts_limits
                    .get(source_id)
                    .ok_or(KernelError::Bundle)?;
                self.runtime
                    .prepare_with_prior_facts(script, selectors, &parameters, prior_facts, limits)
                    .map(PreparedSourceRequest::Http)
                    .map_err(|_| KernelError::Preparation)
            }
            // A statement source without a preparation script prepares nothing:
            // every parameter it binds comes from its declared bindings, and an
            // empty preparation result says exactly that.
            SourceConfig::SqliteExtract { .. } => {
                let Some(script) = self.preparations.get(source_id) else {
                    return Ok(PreparedSourceRequest::Statement(StatementParameters {
                        parameters: BTreeMap::new(),
                    }));
                };
                let limits = self
                    .statement_parameters_limits
                    .get(source_id)
                    .ok_or(KernelError::Bundle)?;
                self.runtime
                    .prepare_statement_with_prior_facts(
                        script,
                        selectors,
                        &parameters,
                        prior_facts,
                        limits,
                    )
                    .map(PreparedSourceRequest::Statement)
                    .map_err(|_| KernelError::Preparation)
            }
        }
    }

    /// Prepare one optimized HTTP source call for several logical lookups.
    ///
    /// Every selector object is revalidated against the source's compiled
    /// role/profile/field declarations before Rust assigns its opaque integer
    /// slot. The script therefore receives no caller key, no extra selector
    /// field, and no transport authority.
    pub fn prepare_source_batch(
        &self,
        source_id: &str,
        selector_items: &[Value],
    ) -> Result<PreparedSourceBatch, KernelError> {
        let source = self
            .bundle
            .config
            .sources
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let batch = source.batch().ok_or(KernelError::Bundle)?;
        if selector_items.is_empty()
            || selector_items.len() > usize::from(batch.maximum_items)
            || !batch_selector_items_are_exact(
                source,
                &self.bundle.config.source_selector_sets(source_id),
                selector_items,
            )
        {
            return Err(KernelError::Preparation);
        }
        let slots = (0..selector_items.len())
            .map(|slot| i64::try_from(slot).map_err(|_| KernelError::Preparation))
            .collect::<Result<Vec<_>, _>>()?;
        let items = Value::Array(
            slots
                .iter()
                .zip(selector_items)
                .map(|(slot, selectors)| {
                    Value::Object(JsonMap::from_iter([
                        ("slot".to_owned(), Value::from(*slot)),
                        ("selectors".to_owned(), selectors.clone()),
                    ]))
                })
                .collect(),
        );
        let parameters =
            serde_json::to_value(source.adapter_parameters()).map_err(|_| KernelError::Bundle)?;
        let script = self
            .batch_preparations
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let limits = self
            .request_parts_limits
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let request = self
            .runtime
            .prepare_batch(script, &items, &parameters, limits)
            .map(PreparedSourceBatchRequest::new)
            .map_err(|_| KernelError::Preparation)?;
        let adapter_id = Path::new(batch.extract_script.as_str())
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or(KernelError::Bundle)?
            .to_owned();
        Ok(PreparedSourceBatch {
            source_id: source_id.to_owned(),
            adapter_id,
            slots,
            request,
        })
    }

    /// Validate one projected batch response, run its reviewed extraction,
    /// require an exact slot bijection, and return logical request order.
    pub fn extract_source_batch(
        &self,
        prepared: &PreparedSourceBatch,
        source_response: &Value,
    ) -> Result<Vec<LookupResult>, KernelError> {
        let source = self
            .bundle
            .config
            .sources
            .get(&prepared.source_id)
            .ok_or(KernelError::Bundle)?;
        let batch = source.batch().ok_or(KernelError::Bundle)?;
        let response_schema = self
            .batch_response_schemas
            .get(&prepared.source_id)
            .ok_or(KernelError::Bundle)?;
        if let Err(errors) = response_schema.validate(source_response) {
            report_response_shape_rejection(
                &prepared.source_id,
                batch.response_schema.as_str(),
                errors,
            );
            return Err(KernelError::SourceProtocol);
        }
        let script = self
            .batch_extractions
            .get(&prepared.source_id)
            .ok_or(KernelError::Bundle)?;
        let fact_schema = self
            .fact_schemas
            .get(&prepared.source_id)
            .ok_or(KernelError::Bundle)?;
        let parameters =
            serde_json::to_value(source.adapter_parameters()).map_err(|_| KernelError::Bundle)?;
        self.runtime
            .extract_batch(
                script,
                source_response,
                &parameters,
                &prepared.slots,
                fact_schema,
            )
            // A batch extraction has one global protocol boundary. A malformed
            // outer result, malformed member, invalid FactSet, invocation
            // failure, or slot failure cannot be collapsed into one logical
            // item's unavailable outcome. Only a successfully decoded
            // `LookupResult::NoMatch` or `Ambiguous` can take that lane.
            .map_err(batch_extraction_failure)
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
        let source_id = requirement.acquisition.initial_source();
        self.extract_source(source_id, source_response, &BTreeMap::new())
    }

    /// Run one source's closed extraction ABI over one bounded projected JSON
    /// response and the exact prior search facts supplied to that call.
    pub fn extract_source(
        &self,
        source_id: &str,
        source_response: &Value,
        prior_facts: &BTreeMap<String, Value>,
    ) -> Result<LookupResult, KernelError> {
        self.extract_source_with_policy(
            source_id,
            source_response,
            prior_facts,
            ExtractionFailurePolicy::Ordinary,
        )
    }

    /// Extract one sequential request-batch stage without allowing malformed
    /// script output or an invalid FactSet to become one item's unavailable
    /// result. Genuine `required(...)` unavailability retains that per-item
    /// collapse; protocol violations abort the atomic outer batch.
    pub(crate) fn extract_source_for_request_batch(
        &self,
        source_id: &str,
        source_response: &Value,
        prior_facts: &BTreeMap<String, Value>,
    ) -> Result<LookupResult, KernelError> {
        self.extract_source_with_policy(
            source_id,
            source_response,
            prior_facts,
            ExtractionFailurePolicy::RequestBatch,
        )
    }

    fn extract_source_with_policy(
        &self,
        source_id: &str,
        source_response: &Value,
        prior_facts: &BTreeMap<String, Value>,
        failure_policy: ExtractionFailurePolicy,
    ) -> Result<LookupResult, KernelError> {
        let script = self.extractions.get(source_id).ok_or(KernelError::Bundle)?;
        let schema = self
            .fact_schemas
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let source = self
            .bundle
            .config
            .sources
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        // The declared response shape is checked in Rust before any script sees
        // the response, so extraction maps a response it can rely on and a
        // provider that breaks its protocol fails closed the same way whether
        // or not the script happens to test for it.
        let response_schema = self
            .response_schemas
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        if let Err(errors) = response_schema.validate(source_response) {
            report_response_shape_rejection(source_id, source.response_schema().as_str(), errors);
            return Err(KernelError::SourceProtocol);
        }
        let parameters =
            serde_json::to_value(source.adapter_parameters()).map_err(|_| KernelError::Bundle)?;
        self.runtime
            .extract_with_prior_facts(script, source_response, &parameters, prior_facts, schema)
            .map_err(|error| extraction_failure(error, failure_policy))
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
            subject_binding: input.scope.mode(),
            request_nonce: input.scope.request_nonce().map(ToOwned::to_owned),
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
            audience: input.scope.audience().map(ToOwned::to_owned),
            configuration_revision: self
                .bundle
                .configuration_revision(&requirement.id)
                .ok_or(KernelError::Requirement)?
                .to_owned(),
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
/// same `source.unavailable`, which sends an operator to the provider for a
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

/// Compile one reviewed schema artifact under the full Draft 2020-12 gate.
///
/// The compiler's own message quotes the schema node it rejected, so only the
/// artifact and a static cause survive the boundary.
fn compile_schema(artifact: &str, schema: &Value) -> Result<JSONSchema, KernelError> {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| refuse_artifact(artifact, "schema is not a valid JSON Schema"))
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
        let handle = CodelistHandle::new(entries)
            .map_err(|_| refuse_artifact(path, "codelist exceeds a runtime bound"))?;
        // Derivation names a codelist by file stem, so two codelists that share
        // one stem in different directories are indistinguishable to a script.
        if handles.insert(name.to_owned(), handle).is_some() {
            return Err(refuse_artifact(path, "codelist file stem is duplicated"));
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
    // An entity reference is audience-scoped by construction and by its public
    // `form`. A holder-bound assertion names no audience, so there is nothing to
    // scope one to and the projection refuses rather than inventing a scope.
    let audience = projection.scope.audience().ok_or(KernelError::Output)?;
    let reference = entity_reference(
        projection.binding_key,
        projection.binding_key_version,
        &concept.id,
        audience,
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
        || !scope_is_valid(input.scope)
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

/// A holder-bound scope carries nothing to validate. An audience-scoped one
/// keeps the bounds it has always had on both of its members.
fn scope_is_valid(scope: EvidenceScope<'_>) -> bool {
    match scope {
        EvidenceScope::AudienceScoped {
            audience,
            request_nonce,
        } => {
            crate::model::request_nonce_is_canonical(request_nonce)
                && !audience.is_empty()
                && audience.len() <= MAXIMUM_EVIDENCE_IDENTIFIER_BYTES
                && url::Url::parse(audience).is_ok()
        }
        EvidenceScope::HolderBound => true,
    }
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

    use crate::rhai_runtime::RequestParts;
    use crate::signing::{jwks_document, EvidenceSigner};
    use crate::source::project_fixture_response;
    use crate::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const AUDIENCE: &str = "urn:example:fixture:audience";
    const SUPPORTED_VALUE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const SUPPORTED_VALUE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
    /// A value a diagnostic must never echo, in the shape a script scalar has.
    const SCRIPT_CANARY: &str = "0451-mrs-hunt-was-born-in-caracas";
    /// A function the loader's permissive engine accepts and the hardened
    /// kernel grammar refuses, so the kernel is the pass that has to report it.
    fn refused_by_the_hardened_grammar() -> String {
        format!("\nfn unreviewed() {{\n    let value = \"{SCRIPT_CANARY}\";\n    while false {{ }}\n    value\n}}\n")
    }

    fn projection() -> ValueProjection<'static> {
        ValueProjection {
            scope: EvidenceScope::AudienceScoped {
                audience: AUDIENCE,
                request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
            },
            binding_key: KEY,
            binding_key_version: 1,
        }
    }

    #[test]
    fn source_batch_items_are_revalidated_as_exact_minimized_selectors() {
        let source: SourceConfig = serde_json::from_value(json!({
            "transport": "http-json",
            "baseUrl": "https://source.invalid",
            "posture": "field-projected",
            "authentication": {"kind": "static-authorization", "tokenRef": "secret:file/source"},
            "request": {
                "method": "POST",
                "path": "/facts",
                "fixedHeaders": [],
                "selectorInputs": [{
                    "role": "subject",
                    "alternatives": [{"profile": "opaque-v1", "fields": ["id"]}]
                }],
                "prepareScript": "adapters/prepare.rhai",
                "adapterParameters": {},
                "adapterParametersSchema": "schemas/parameters.schema.yaml",
                "preparationLimits": {"query": "forbidden", "jsonBody": "required"},
                "projection": ["/result"],
                "redirects": "deny",
                "timeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "concurrencyLimit": 1
            },
            "responseSchema": "schemas/response.schema.yaml",
            "extractScript": "adapters/extract.rhai",
            "factSchema": "schemas/facts.schema.yaml",
            "batch": {
                "maximumItems": 2,
                "prepareScript": "adapters/prepare-batch.rhai",
                "extractScript": "adapters/extract-batch.rhai",
                "responseSchema": "schemas/batch-response.schema.yaml",
                "projection": ["/results/*"]
            }
        }))
        .expect("source deserializes");
        let allowed = vec![vec![("subject".to_owned(), "opaque-v1".to_owned())]];
        let minimized = json!({
            "subject": {"profile": "opaque-v1", "values": {"id": "synthetic"}}
        });
        assert!(batch_selector_items_are_exact(
            &source,
            &allowed,
            std::slice::from_ref(&minimized)
        ));
        for expanded in [
            json!({
                "subject": {"profile": "opaque-v1", "values": {"id": "synthetic", "extra": "leak"}}
            }),
            json!({
                "subject": {"profile": "opaque-v1", "values": {"id": "synthetic"}, "headers": {"x": "authority"}}
            }),
            json!({
                "subject": {"profile": "other-v1", "values": {"id": "synthetic"}}
            }),
            json!({
                "subject": {"profile": "opaque-v1", "values": {"id": "synthetic"}},
                "other": {"profile": "opaque-v1", "values": {"id": "cross-slot"}}
            }),
        ] {
            assert!(
                !batch_selector_items_are_exact(&source, &allowed, &[expanded]),
                "expanded selector material reached batch preparation"
            );
        }
    }

    #[test]
    fn every_malformed_batch_extraction_is_a_global_protocol_failure() {
        let kernel = batch_extraction_kernel();
        let prepared = PreparedSourceBatch {
            source_id: "source-a".to_owned(),
            adapter_id: "extract-batch".to_owned(),
            slots: vec![0, 1],
            request: PreparedSourceBatchRequest::new(RequestParts {
                query: Vec::new(),
                body: None,
            }),
        };
        for (label, kind) in [
            ("wrong outer shape", "wrong-outer"),
            ("wrong member shape", "wrong-member"),
            ("member keys are not exact", "extra-key"),
            ("FactSet violates the source fact schema", "invalid-facts"),
            ("missing slot", "missing"),
            ("duplicate slot", "duplicate"),
            ("extra slot", "extra"),
            ("out-of-range slot", "out-of-range"),
            ("negative slot", "negative"),
        ] {
            assert_eq!(
                kernel.extract_source_batch(&prepared, &json!({"kind": kind})),
                Err(KernelError::SourceProtocol),
                "{label} could collapse into a per-item unavailable outcome"
            );
        }
    }

    fn batch_extraction_kernel() -> OfflineKernel {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status");
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_tree(&source, temporary.path());
        let config_path = temporary.path().join("evidence.yaml");
        let config = fs::read_to_string(&config_path).expect("configuration reads");
        assert_eq!(config.matches("version: 1\n").count(), 1);
        assert_eq!(
            config
                .matches("    factSchema: schemas/facts.schema.yaml\n")
                .count(),
            1
        );
        let config = config
            .replacen(
                "version: 1\n",
                "version: 1\nacquisitionCapabilities: [source-batch]\n",
                1,
            )
            .replacen(
                "    factSchema: schemas/facts.schema.yaml\n",
                "    factSchema: schemas/facts.schema.yaml\n    batch:\n      maximumItems: 2\n      prepareScript: adapters/prepare-batch.rhai\n      extractScript: adapters/extract-batch.rhai\n      responseSchema: schemas/batch-response.schema.yaml\n      projection: [/output]\n",
                1,
            );
        fs::write(config_path, config).expect("configuration writes");
        fs::write(
            temporary.path().join("adapters/prepare-batch.rhai"),
            "fn prepare_batch(items, context) { #{query: [], body: #{items: items}} }\n",
        )
        .expect("batch preparation writes");
        fs::write(
            temporary.path().join("adapters/extract-batch.rhai"),
            r#"
fn extract_batch(response, context) {
    if response.kind == "wrong-outer" {
        return #{};
    }
    if response.kind == "wrong-member" {
        return [0, #{slot: 1, result: #{outcome: "no_match"}}];
    }
    if response.kind == "extra-key" {
        return [
            #{slot: 0, result: #{outcome: "no_match"}, extra: true},
            #{slot: 1, result: #{outcome: "no_match"}}
        ];
    }
    if response.kind == "invalid-facts" {
        return [
            #{slot: 0, result: #{outcome: "match", facts: #{unexpected: true}}},
            #{slot: 1, result: #{outcome: "no_match"}}
        ];
    }
    if response.kind == "missing" {
        return [#{slot: 0, result: #{outcome: "no_match"}}];
    }
    if response.kind == "duplicate" {
        return [
            #{slot: 0, result: #{outcome: "no_match"}},
            #{slot: 0, result: #{outcome: "no_match"}}
        ];
    }
    if response.kind == "extra" {
        return [
            #{slot: 0, result: #{outcome: "no_match"}},
            #{slot: 1, result: #{outcome: "no_match"}},
            #{slot: 2, result: #{outcome: "no_match"}}
        ];
    }
    if response.kind == "out-of-range" {
        return [
            #{slot: 0, result: #{outcome: "no_match"}},
            #{slot: 2, result: #{outcome: "no_match"}}
        ];
    }
    [
        #{slot: 0, result: #{outcome: "no_match"}},
        #{slot: -1, result: #{outcome: "no_match"}}
    ]
}
"#,
        )
        .expect("batch extraction writes");
        fs::write(
            temporary
                .path()
                .join("schemas/batch-response.schema.yaml"),
            "$schema: https://json-schema.org/draft/2020-12/schema\ntype: object\nadditionalProperties: false\nrequired: [kind]\nproperties:\n  kind:\n    type: string\n    enum: [wrong-outer, wrong-member, extra-key, invalid-facts, missing, duplicate, extra, out-of-range, negative]\n",
        )
        .expect("batch response schema writes");
        make_read_only(temporary.path());
        let bundle = Arc::new(Bundle::load(temporary.path()).expect("batch bundle loads"));
        OfflineKernel::compile(bundle).expect("batch kernel compiles")
    }

    #[test]
    fn kernel_compilation_names_every_script_artifact_it_refuses() {
        for artifact in [
            "adapters/source-a-prepare.rhai",
            "adapters/source-a.rhai",
            "derivations/adult-status.rhai",
        ] {
            let copied = fixture_with_appended_artifact(
                "adult-status",
                artifact,
                &refused_by_the_hardened_grammar(),
            );
            let bundle = Arc::new(Bundle::load(copied.path()).expect("the loader accepts it"));

            let error = OfflineKernel::compile(bundle).expect_err("the kernel refuses it");

            let fault = error
                .artifact_fault()
                .unwrap_or_else(|| panic!("{artifact}: the failure names no artifact"));
            assert_eq!(fault.artifact(), artifact);
            assert_eq!(fault.fault().cause(), "script does not compile");
        }
    }

    /// The engine reports a compilation failure by quoting the source it
    /// rejected. That text reaches an operator ticket, so the boundary keeps
    /// the artifact and one static cause and discards everything else.
    #[test]
    fn a_refused_artifact_discloses_no_script_text() {
        let copied = fixture_with_appended_artifact(
            "adult-status",
            "derivations/adult-status.rhai",
            &refused_by_the_hardened_grammar(),
        );
        let bundle = Arc::new(Bundle::load(copied.path()).expect("the loader accepts it"));

        let error = OfflineKernel::compile(bundle).expect_err("the kernel refuses it");

        let rendered = format!(
            "{error}: {}",
            error
                .artifact_fault()
                .expect("the failure names an artifact")
        );
        assert!(!rendered.contains(SCRIPT_CANARY), "{rendered}");
        assert!(!rendered.contains("while"), "{rendered}");
        assert!(!rendered.contains("unreviewed"), "{rendered}");
    }

    /// A lookup that configuration validation already proved is an internal
    /// invariant, not an artifact an adopter can repair. It names no file, and
    /// gaining an artifact diagnostic would invent one.
    #[test]
    fn an_internal_invariant_failure_is_not_dressed_up_as_an_artifact_fault() {
        assert!(KernelError::Bundle.artifact_fault().is_none());
        assert!(KernelError::Requirement.artifact_fault().is_none());
        assert!(KernelError::Script.artifact_fault().is_none());
        assert!(
            refuse_artifact("codelists/regions.yaml", "codelist file stem is duplicated")
                .artifact_fault()
                .is_some()
        );
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
                .get(requirement.acquisition.initial_source())
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

    /// A shape rejection reaches the requester as `source.unavailable`,
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
            .get(requirement.acquisition.initial_source())
            .expect("the requirement names a configured source");
        let schema = bundle
            .fact_schema(source.response_schema())
            .expect("the response schema is a bundle artifact");
        let compiled = compile_schema(source.response_schema().as_str(), schema)
            .expect("the response schema compiles");

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
    fn sequential_request_batch_extraction_distinguishes_unavailability_from_protocol_faults() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(bundle).expect("kernel compiles");
        let prior_facts = BTreeMap::new();

        // The frozen singular lane continues to collapse an invalid extracted
        // FactSet, while the atomic outer batch treats it as a global source
        // protocol failure.
        let response = json!({"total": 1});
        assert_eq!(
            kernel.extract_source("source-a", &response, &prior_facts),
            Err(KernelError::Extraction)
        );
        assert_eq!(
            kernel.extract_source_for_request_batch("source-a", &response, &prior_facts),
            Err(KernelError::SourceProtocol)
        );

        let malformed = kernel_with_adult_extraction(
            r#"fn extract(source_response, context) {
    #{outcome: "no_match", extra: true}
}
"#,
        );
        let response = json!({"total": 0});
        assert_eq!(
            malformed.extract_source("source-a", &response, &prior_facts),
            Err(KernelError::Extraction),
            "singular behavior remains frozen"
        );
        assert_eq!(
            malformed.extract_source_for_request_batch("source-a", &response, &prior_facts),
            Err(KernelError::SourceProtocol),
            "malformed ordinary extraction output aborts the outer batch"
        );

        let unavailable = kernel_with_adult_extraction(
            r#"fn extract(source_response, context) {
    required(get_path(source_response, "/date_of_birth"), "required_fact_missing");
    #{outcome: "no_match"}
}
"#,
        );
        let response = json!({"total": 1});
        assert_eq!(
            unavailable.extract_source_for_request_batch("source-a", &response, &prior_facts),
            Err(KernelError::Extraction),
            "genuine required-value unavailability remains a per-item outcome"
        );
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
        let schema = compile_schema(
            "schemas/structured.schema.yaml",
            &json!({
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
            }),
        )
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
            purpose: &requirement.purposes[0],
            scope: EvidenceScope::AudienceScoped {
                audience: AUDIENCE,
                request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
            },
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

    /// A holder-bound construction has no member in which to state an audience
    /// or a request nonce, so the constructed payload cannot carry either and
    /// still agrees with the mode it declares.
    #[test]
    fn a_holder_bound_construction_states_no_audience_and_no_request_nonce() {
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
        let evidence = kernel
            .construct_evidence(
                &requirement.id,
                values,
                EvidenceConstruction {
                    evidence_id: "urn:ulid:01K1EXAMPLE0000000000000000",
                    purpose: &requirement.purposes[0],
                    scope: EvidenceScope::HolderBound,
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
                },
            )
            .expect("constructs");
        assert_eq!(evidence.subject_binding, SubjectBindingMode::HolderBound);
        assert_eq!(evidence.audience, None);
        assert_eq!(evidence.request_nonce, None);
        registry_evidence_verifier::model::validate_subject_binding_shape(&evidence)
            .expect("the constructed members agree with the declared mode");
    }

    /// An entity reference is scoped to an audience by its own public `form`.
    /// A holder-bound projection names no audience, so the projection refuses
    /// rather than inventing one.
    #[test]
    fn an_entity_reference_has_no_holder_bound_projection() {
        let entity = concept(
            "form: audience-scoped-entity-reference\nrequired: true\nconstraints: {maximumBytes: 160}",
        );
        let seed = crate::values::EntityReferenceSeed::new("protected-seed").expect("seed");
        let holder_bound = ValueProjection {
            scope: EvidenceScope::HolderBound,
            binding_key: KEY,
            binding_key_version: 1,
        };
        assert!(matches!(
            validate_value(
                &entity,
                &DerivedValue::EntityReferenceSeed(seed),
                &holder_bound,
                &BTreeMap::new(),
                &BTreeMap::new(),
            ),
            Err(KernelError::Output)
        ));
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
        let aggregate_schema = compile_schema(
            "schemas/aggregate.schema.yaml",
            &json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": aggregate_schema_id,
                "type": "object",
                "additionalProperties": false,
                "required": ["blob"],
                "properties": {"blob": {"type": "string", "maxLength": 5000}}
            }),
        )
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
                    purpose: "conformance",
                    scope: EvidenceScope::AudienceScoped {
                        audience: AUDIENCE,
                        request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                    },
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
                evidence
                    .request_nonce
                    .as_deref()
                    .expect("the fixture is audience-scoped"),
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
        serde_norway::from_str(&format!(
            "handle: example-concept\nid: urn:example:concept\n{body}\n"
        ))
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

    /// One acceptance bundle whose named artifact gained text before loading.
    ///
    /// The bundle is still immutable when it loads, so the copy is locked after
    /// the edit exactly as an untouched copy is.
    fn fixture_with_appended_artifact(name: &str, artifact: &str, appended: &str) -> TempDir {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(name);
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_tree(&source, temporary.path());
        let path = temporary.path().join(artifact);
        let mut text = fs::read_to_string(&path).expect("reads copied artifact");
        text.push_str(appended);
        fs::write(&path, text).expect("writes copied artifact");
        make_read_only(temporary.path());
        temporary
    }

    fn kernel_with_adult_extraction(extraction: &str) -> OfflineKernel {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status");
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_tree(&source, temporary.path());
        fs::write(temporary.path().join("adapters/source-a.rhai"), extraction)
            .expect("replacement extraction writes");
        make_read_only(temporary.path());
        let bundle = Arc::new(Bundle::load(temporary.path()).expect("bundle loads"));
        OfflineKernel::compile(bundle).expect("kernel compiles")
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
