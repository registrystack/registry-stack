//! Generic offline Evidence evaluation and core-owned output projection.
//!
//! This module deliberately knows nothing about an acceptance case or source
//! product. It joins one captured verified package to the hardened Rhai runtime,
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
use crate::config::{ConceptConfig, ConceptForm, RequirementConfig, SchemaFault};
use crate::model::{
    BucketForm, BucketValue, EntityReferenceForm, EntityReferenceValue, Evidence,
    EvidenceObjectType, LookupResult, PublicValue, ScalarOrEntityReference, StructuredValue,
    StructuredValueForm, SubjectBinding, SubjectBindingMode, SupportedValue,
};
use crate::rhai_runtime::{
    CalendarDate, CodelistHandle, CompiledDerivation, DerivedConceptValue, DerivedValue,
    EvaluationContext, LegalLocalTime, RhaiRuntime, RhaiRuntimeError, UtcInstant,
    MAXIMUM_RESULT_BYTES,
};
use crate::values::Decimal;

const MAXIMUM_PUBLIC_STRING_BYTES: usize = 1_024;
const MAXIMUM_BUCKET_CODE_BYTES: usize = 128;
const MAXIMUM_EVIDENCE_IDENTIFIER_BYTES: usize = 512;

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
    #[error("the acquired facts exceed the derivation input bound")]
    FactsBound,
    #[error("the Evidence script failed")]
    Script,
    #[error("the derived Evidence values violate the requirement contract")]
    Output,
    /// A derived structured value named a property its reviewed schema does
    /// not declare.
    ///
    /// The same output-gate refusal as [`Self::Output`], carried separately so
    /// the offline diagnostic can say which key was undeclared. The property
    /// name travels without its value: it is a structural name the schema
    /// never declared, and nothing about what the derivation put under it is
    /// kept.
    #[error("the derived Evidence values name an undeclared property: {0}")]
    UndeclaredOutputProperty(String),
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

#[derive(Debug, Clone, PartialEq)]
pub enum KernelOutcome {
    Match(ValidatedValues),
    NoMatch,
    Ambiguous,
    Unresolved,
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
    /// Earliest verified deadline of any signed source value used to derive
    /// this assertion. Ordinary HTTP and SQLite sources supply no cap.
    pub source_valid_until: Option<DateTime<Utc>>,
    pub subjects: Vec<SubjectBinding>,
}

/// One reviewed answer schema as the kernel holds it: the compiled validator
/// plus the property names its top level declares, when it declares any.
///
/// The declared names are kept beside the compiled form so the output gate can
/// refuse a key the schema never declared even where the schema document itself
/// predates the closed-authoring rule and still permits one. A schema whose top
/// level declares no `properties` object has no known property set, and only
/// its compiled validation applies.
struct ReviewedSchema {
    compiled: JSONSchema,
    declared_properties: Option<BTreeSet<String>>,
}

impl ReviewedSchema {
    fn compile(artifact: &str, schema: &Value) -> Result<Self, KernelError> {
        let compiled = compile_schema(artifact, schema)?;
        let declared_properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect::<BTreeSet<_>>());
        Ok(Self {
            compiled,
            declared_properties,
        })
    }
}

/// A kernel compiled entirely from the bytes captured in one immutable bundle.
pub struct OfflineKernel {
    bundle: Arc<Bundle>,
    runtime: RhaiRuntime,
    derivations: BTreeMap<String, CompiledDerivation>,
    fact_schemas: BTreeMap<String, JSONSchema>,
    reviewed_schemas: BTreeMap<String, ReviewedSchema>,
    codelist_handles: BTreeMap<String, BTreeMap<String, CodelistHandle>>,
}

impl std::fmt::Debug for OfflineKernel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineKernel")
            .field("package_digest", &self.bundle.package_digest())
            .field("source_count", &self.fact_schemas.len())
            .field("requirement_count", &self.derivations.len())
            .finish()
    }
}

impl OfflineKernel {
    pub fn compile(bundle: Arc<Bundle>) -> Result<Self, KernelError> {
        let runtime = RhaiRuntime::new();
        let mut fact_schemas = BTreeMap::new();
        for (source_id, source) in bundle.config.sources.iter() {
            let schema = bundle
                .fact_schema(source.fact_schema())
                .ok_or(KernelError::Bundle)?;
            fact_schemas.insert(
                source_id.to_owned(),
                compile_schema(source.fact_schema().as_str(), schema)?,
            );
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
                    .insert(
                        identifier.to_owned(),
                        ReviewedSchema::compile(path, schema)?,
                    )
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
            derivations,
            fact_schemas,
            reviewed_schemas,
            codelist_handles,
        })
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

    /// Validate a completed pack-route lookup before offline derivation. Raw
    /// provider responses never enter this API; acquisition runs in the engine.
    pub fn validate_lookup(
        &self,
        source_id: &str,
        outcome: &Value,
    ) -> Result<LookupResult, KernelError> {
        let schema = self
            .fact_schemas
            .get(source_id)
            .ok_or(KernelError::Bundle)?;
        let lookup: registry_adapter_engine::evidence::EvidenceLookup =
            serde_json::from_value(outcome.clone()).map_err(|_| KernelError::SourceProtocol)?;
        match lookup {
            registry_adapter_engine::evidence::EvidenceLookup::Matched {
                facts: Value::Object(facts),
            } => {
                if !schema.is_valid(&Value::Object(facts.clone())) {
                    return Err(KernelError::SourceProtocol);
                }
                Ok(LookupResult::Match(facts.into_iter().collect()))
            }
            registry_adapter_engine::evidence::EvidenceLookup::Matched { .. } => {
                Err(KernelError::SourceProtocol)
            }
            registry_adapter_engine::evidence::EvidenceLookup::NoMatch => Ok(LookupResult::NoMatch),
            registry_adapter_engine::evidence::EvidenceLookup::Unresolved => {
                Ok(LookupResult::Unresolved)
            }
            registry_adapter_engine::evidence::EvidenceLookup::Ambiguous => {
                Ok(LookupResult::Ambiguous)
            }
        }
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
                RhaiRuntimeError::FactsBound => KernelError::FactsBound,
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
        let source_id = &self
            .requirement(requirement_id)
            .ok_or(KernelError::Requirement)?
            .acquisition
            .source;
        match self.validate_lookup(source_id, source_response)? {
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
            LookupResult::Unresolved => Ok(KernelOutcome::Unresolved),
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
        // The public contract emits whole-second instants. Apply lifecycle
        // comparisons at that same precision so sub-second differences cannot
        // collapse into an invalid `issuedAt == validUntil` payload after
        // serialization. Flooring a source deadline is conservative: the
        // downstream assertion remains bounded by the exact verified instant.
        let issued_at = emitted_instant(input.issued_at)?;
        let local_valid_until = issued_at
            .checked_add_signed(Duration::seconds(
                i64::try_from(requirement.validity_seconds.get())
                    .map_err(|_| KernelError::Evidence)?,
            ))
            .ok_or(KernelError::Evidence)?;
        let valid_until = input
            .source_valid_until
            .map(emitted_instant)
            .transpose()?
            .map_or(local_valid_until, |source| source.min(local_valid_until));
        if valid_until <= issued_at {
            return Err(KernelError::Evidence);
        }
        let valid_until = format_utc(valid_until);

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

/// Compile one reviewed schema artifact under the full Draft 2020-12 gate.
///
/// The compiler's own message quotes the schema node it rejected, so only the
/// artifact and a static cause survive the boundary.
fn compile_schema(artifact: &str, schema: &Value) -> Result<JSONSchema, KernelError> {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_format("uuid", crate::selector::canonical_uuid)
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
    reviewed_schemas: &BTreeMap<String, ReviewedSchema>,
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
    reviewed_schemas: &BTreeMap<String, ReviewedSchema>,
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
        ConceptForm::BoundedIdentifier => {
            let text = derived_string(value)?;
            let prefix = constraint_str(concept, "prefix")?;
            let suffix = text.strip_prefix(prefix).ok_or(KernelError::Output)?;
            let minimum = constraint_usize(concept, "minimumBytes")?;
            let maximum = constraint_usize(concept, "maximumBytes")?;
            if text.len() < minimum
                || suffix.is_empty()
                || !suffix.as_bytes()[0].is_ascii_alphanumeric()
                || !suffix.as_bytes()[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(KernelError::Output);
            }
            validate_public_string(text, maximum)?;
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
    schemas: &BTreeMap<String, ReviewedSchema>,
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
    // Defense in depth for the closed-authoring rule: where the reviewed
    // schema's top level declares its property set, a key outside that set is
    // refused here even if the schema document predates the rule and still
    // permits undeclared properties. Checked before the compiled validation so
    // the refusal can name the key rather than only the shape it broke.
    if let Some(declared) = &schema.declared_properties {
        if let Some(undeclared) = fields.keys().find(|key| !declared.contains(key.as_str())) {
            return Err(KernelError::UndeclaredOutputProperty(undeclared.clone()));
        }
    }
    let fields_value = Value::Object(fields.clone());
    if !schema.compiled.is_valid(&fields_value) {
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

fn emitted_instant(value: DateTime<Utc>) -> Result<DateTime<Utc>, KernelError> {
    DateTime::from_timestamp(value.timestamp(), 0).ok_or(KernelError::Evidence)
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

/// Check one projected list against the range its concept declares.
///
/// The declared range itself is not in question here.
/// `validate_collection_constraints` refuses an incoherent or out-of-range
/// declaration while the bundle loads, over every concept of every
/// requirement, so a deployment whose declaration is unsound never starts and
/// this never sees one. What is in question is the length a derivation
/// actually produced for this one question, which nothing before the
/// projection knows.
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
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
    use serde_json::json;
    use tempfile::TempDir;

    use crate::fixture_source::{compile_sources, fixture_acquisition};
    use crate::selector::resolve_offline_fixture_authorization;
    use crate::signing::{jwks_document, EvidenceSigner};
    use crate::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const AUDIENCE: &str = "urn:example:fixture:audience";
    const SUPPORTED_VALUE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const SUPPORTED_VALUE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
    /// A value a diagnostic must never echo, in the shape a script scalar has.
    const SCRIPT_CANARY: &str = "0451-mrs-hunt-was-born-in-caracas";

    /// Opt-in CPU measurement with startup and source I/O outside the clock.
    /// Run with `cargo test --locked --release -p registry-evidence --lib
    /// completed_lookup_validation_performance -- --ignored --nocapture`.
    /// Reports batch-average samples without a host-dependent assertion.
    #[test]
    #[ignore = "opt-in completed lookup validation CPU benchmark"]
    fn completed_lookup_validation_performance() {
        use std::hint::black_box;
        use std::time::Instant;

        fn measure(label: &str, iterations: u32, mut operation: impl FnMut()) {
            for _ in 0..1_000 {
                operation();
            }
            let mut samples = Vec::new();
            for _ in 0..7 {
                let started = Instant::now();
                for _ in 0..iterations {
                    operation();
                }
                samples.push(started.elapsed().as_nanos() / u128::from(iterations));
            }
            println!("{label}: iterations={iterations} ns_per_op={samples:?}");
        }

        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let lookup = json!({
            "lookup": "matched",
            "facts": {"date_of_birth": "1970-01-01"}
        });
        measure("completed-lookup-validation", 20_000, || {
            assert!(matches!(
                black_box(kernel.validate_lookup(
                    black_box(requirement.acquisition.initial_source()),
                    black_box(&lookup)
                )),
                Ok(LookupResult::Match(_))
            ));
        });
    }
    /// A function the loader's permissive engine accepts and the hardened
    /// kernel grammar refuses, so the kernel is the pass that has to report it.
    fn refused_by_the_hardened_grammar() -> String {
        format!(
            "\nfn unreviewed() {{\n    let value = \"{SCRIPT_CANARY}\";\n    while false {{ }}\n    value\n}}\n"
        )
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
    fn completed_lookup_is_closed_and_fact_schema_validated() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source = bundle.config.requirements[0].acquisition.initial_source();

        assert_eq!(
            kernel.validate_lookup(
                source,
                &json!({"lookup": "matched", "facts": {"date_of_birth": "1970-01-01"}}),
            ),
            Ok(LookupResult::Match(BTreeMap::from([(
                "date_of_birth".to_owned(),
                json!("1970-01-01"),
            )])))
        );
        for malformed in [
            json!({}),
            json!({"lookup": "matched"}),
            json!({"lookup": "matched", "facts": null}),
            json!({"lookup": "matched", "facts": {"unexpected": true}}),
            json!({"lookup": "no-match", "facts": {}}),
            json!({"lookup": "unresolved", "facts": {}}),
            json!({"lookup": "other"}),
        ] {
            assert_eq!(
                kernel.validate_lookup(source, &malformed),
                Err(KernelError::SourceProtocol),
                "malformed completed lookup was accepted: {malformed}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn current_pack_replay_uses_minimized_inputs_and_refuses_malformed_provider_data() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let requirement = &bundle.config.requirements[0];
        let fixture = bundle
            .fixtures
            .get(
                requirement
                    .fixtures
                    .as_ref()
                    .expect("fixture is declared")
                    .as_str(),
            )
            .expect("fixture is captured");
        let common = fixture.get("common").and_then(Value::as_object);
        let case = fixture["cases"][0].as_object().expect("case is an object");
        let resolved =
            resolve_offline_fixture_authorization(&bundle, requirement, common, case, AUDIENCE)
                .expect("fixture authorization resolves");
        let programs = compile_sources(&bundle).expect("source packs compile");
        let program = programs
            .get(requirement.acquisition.initial_source())
            .expect("source program exists");
        let observed = observed_for_case(fixture, &Value::Object(case.clone()));

        let acquisition = fixture_acquisition(case.get("source").expect("source is recorded"))
            .expect("transcript parses");
        assert!(matches!(
            program.execute(&resolved, acquisition, observed).await,
            Ok(LookupResult::Match(_))
        ));

        let mut malformed = case.get("source").expect("source is recorded").clone();
        malformed["exchanges"][0]["response"]["body"]["date_of_birth"] = json!(SCRIPT_CANARY);
        let acquisition = fixture_acquisition(&malformed).expect("transcript parses");
        let error = program
            .execute(&resolved, acquisition, observed)
            .await
            .expect_err("an invalid provider response reached the completed lookup boundary");
        assert_eq!(error, KernelError::SourceProtocol);
        assert!(
            !format!("{error:?}").contains(SCRIPT_CANARY),
            "provider values must not enter the protocol failure"
        );
    }

    #[test]
    fn kernel_compilation_names_the_derivation_artifact_it_refuses() {
        let artifact = "derivations/adult-status.rhai";
        let copied = fixture_with_appended_artifact(
            "adult-status",
            artifact,
            &refused_by_the_hardened_grammar(),
        );
        let bundle = Arc::new(Bundle::load(copied.path()).expect("the loader accepts it"));

        let error = OfflineKernel::compile(bundle).expect_err("the kernel refuses it");

        let fault = error
            .artifact_fault()
            .expect("the failure names the derivation artifact");
        assert_eq!(fault.artifact(), artifact);
        assert_eq!(fault.fault().cause(), "script does not compile");
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

    #[tokio::test(flavor = "multi_thread")]
    async fn all_four_acceptance_bundles_use_current_pack_replay_and_the_same_kernel() {
        let cases = [
            ("adult-status", 10),
            ("residence-region", 8),
            ("professional-licence", 9),
            ("legal-parent-relationship", 19),
        ];
        for (case, expected_source_cases) in cases {
            let copied = immutable_fixture(case);
            let bundle = Arc::new(Bundle::load(copied.path()).expect("acceptance bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let requirement = &bundle.config.requirements[0];
            let fixture = bundle
                .fixtures
                .get(
                    requirement
                        .fixtures
                        .as_ref()
                        .expect("acceptance fixture is declared")
                        .as_str(),
                )
                .expect("fixture is captured");
            let common = fixture.get("common").and_then(Value::as_object);
            let programs = compile_sources(&bundle).expect("source packs compile");
            let program = programs
                .get(requirement.acquisition.initial_source())
                .expect("requirement source exists");
            let mut executed_source_cases = 0;
            for test_case in fixture["cases"].as_array().expect("cases is an array") {
                let Some(source) = test_case.get("source") else {
                    continue;
                };
                executed_source_cases += 1;
                let case_object = test_case.as_object().expect("case is an object");
                let resolved = resolve_offline_fixture_authorization(
                    &bundle,
                    requirement,
                    common,
                    case_object,
                    AUDIENCE,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{case}: {} authorization failed: {error:?}",
                        test_case["id"]
                    )
                });
                let observed = observed_for_case(fixture, test_case);
                let selectors = test_case
                    .get("derivationSelectorInputs")
                    .or_else(|| {
                        fixture
                            .get("common")
                            .and_then(|common| common.get("derivationSelectorInputs"))
                    })
                    .cloned()
                    .unwrap_or_else(|| Value::Object(JsonMap::new()));
                let acquisition = fixture_acquisition(source).unwrap_or_else(|error| {
                    panic!("{case}: {} transcript failed: {error:?}", test_case["id"])
                });
                let lookup = program.execute(&resolved, acquisition, observed).await;
                let result = lookup.and_then(|lookup| match lookup {
                    LookupResult::Match(facts) => kernel
                        .derive_and_validate_with_selectors(
                            &requirement.id,
                            &facts,
                            &selectors,
                            observed,
                            projection(),
                        )
                        .map(KernelOutcome::Match),
                    LookupResult::NoMatch => Ok(KernelOutcome::NoMatch),
                    LookupResult::Ambiguous => Ok(KernelOutcome::Ambiguous),
                    LookupResult::Unresolved => Ok(KernelOutcome::Unresolved),
                });
                match test_case.get("expectedLookup").and_then(Value::as_str) {
                    Some("match") => {
                        let KernelOutcome::Match(values) = result.unwrap_or_else(|error| {
                            panic!("{case}: {} failed: {error:?}", test_case["id"])
                        }) else {
                            panic!("{case}: {} expected match", test_case["id"]);
                        };
                        assert!(!values.as_slice().is_empty());
                        if let Some(expected) = test_case.get("expectedValue") {
                            assert_eq!(
                                serde_json::to_value(&values.as_slice()[0].value)
                                    .expect("value serializes"),
                                *expected
                            );
                        }
                    }
                    Some("no_match") => assert!(matches!(result, Ok(KernelOutcome::NoMatch))),
                    Some("ambiguous") => assert!(matches!(result, Ok(KernelOutcome::Ambiguous))),
                    _ if test_case.get("expectedPublicProblem").is_some() => {
                        assert!(
                            result.is_err() || matches!(&result, Ok(KernelOutcome::Unresolved)),
                            "{case}: {} unexpectedly succeeded: {result:?}",
                            test_case["id"]
                        )
                    }
                    other => panic!(
                        "{case}: {} has unsupported expectation {other:?}",
                        test_case["id"]
                    ),
                }
            }
            assert_eq!(
                executed_source_cases, expected_source_cases,
                "{case}: a maintained source transcript was skipped"
            );
        }
    }

    #[test]
    fn completed_lookup_facts_are_validated_before_derivation() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source = bundle.config.requirements[0].acquisition.initial_source();

        for facts in [
            json!({}),
            json!({"unexpected": true}),
            json!({"date_of_birth": 19700101}),
            json!({"date_of_birth": "1970-13-01"}),
        ] {
            assert_eq!(
                kernel.validate_lookup(source, &json!({"lookup": "matched", "facts": facts})),
                Err(KernelError::SourceProtocol),
                "invalid completed facts reached derivation"
            );
        }

        assert_eq!(
            kernel.validate_lookup(source, &json!({"lookup": "no-match"})),
            Ok(LookupResult::NoMatch)
        );
        assert_eq!(
            kernel.validate_lookup(
                source,
                &json!({"lookup": "matched", "facts": {"date_of_birth": "1970-01-01"}}),
            ),
            Ok(LookupResult::Match(BTreeMap::from([(
                "date_of_birth".to_owned(),
                json!("1970-01-01")
            )])))
        );
    }

    #[test]
    fn completed_lookup_outcomes_and_invalid_outputs_fail_closed() {
        let copied = immutable_fixture("adult-status");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        assert_eq!(
            kernel.validate_lookup(
                requirement.acquisition.initial_source(),
                &json!({"lookup": "no-match"})
            ),
            Ok(LookupResult::NoMatch)
        );
        assert_eq!(
            kernel.validate_lookup(
                requirement.acquisition.initial_source(),
                &json!({"lookup": "ambiguous"})
            ),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn required_unmapped_source_fact_is_unavailable_not_a_script_failure() {
        let copied = immutable_fixture("residence-region");
        let bundle = Arc::new(Bundle::load(copied.path()).expect("bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let fixture = bundle
            .fixtures
            .get(
                requirement
                    .fixtures
                    .as_ref()
                    .expect("fixture is declared")
                    .as_str(),
            )
            .expect("fixture is captured");
        let common = fixture.get("common").and_then(Value::as_object);
        let case = fixture["cases"][1].as_object().expect("case is an object");
        assert_eq!(
            case.get("id").and_then(Value::as_str),
            Some("negative-unknown-code")
        );
        let resolved =
            resolve_offline_fixture_authorization(&bundle, requirement, common, case, AUDIENCE)
                .expect("fixture authorization resolves");
        let programs = compile_sources(&bundle).expect("source packs compile");
        let program = programs
            .get(requirement.acquisition.initial_source())
            .expect("source program exists");
        let observed = observed_for_case(fixture, &Value::Object(case.clone()));
        let acquisition = fixture_acquisition(case.get("source").expect("source is recorded"))
            .expect("transcript parses");
        let LookupResult::Match(facts) = program
            .execute(&resolved, acquisition, observed)
            .await
            .expect("source pack completes the lookup")
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
            kernel.derive_and_validate(&requirement.id, &facts, observed, projection(),),
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
                &concept("type: boolean\nrequired: true\nconstraints: {}"),
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
                    "type: bounded-integer\nrequired: true\nconstraints: {minimum: -2, maximum: 2}"
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
                &concept(
                    "type: controlled-code\nrequired: true\nconstraints: {codelist: 'urn:example:codes', codelistVersion: '1', maximumBytes: 8}"
                ),
                &DerivedValue::Json(json!("A")),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::String("A".to_owned()))
        );
        assert_eq!(
            validate_value(
                &concept(
                    "type: bounded-decimal\nrequired: true\nconstraints: {minimum: '-1.5', maximum: '1.5', maximumScale: 2}"
                ),
                &DerivedValue::Decimal(Decimal::parse("0.25").expect("decimal")),
                &projection(),
                &codelists,
                &schemas,
            ),
            Ok(PublicValue::String("0.25".to_owned()))
        );
        assert!(validate_value(
            &concept("type: bounded-decimal\nrequired: true\nconstraints: {minimum: '-1.5', maximum: '1.5', maximumScale: 2}"),
            &DerivedValue::Json(json!(0.25)),
            &projection(),
            &codelists,
            &schemas,
        )
        .is_err());

        let controlled = concept(
            "type: controlled-code-list\nrequired: true\nconstraints: {codelist: 'urn:example:codes', codelistVersion: '1', minimumItems: 1, maximumItems: 2, unique: true}",
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
                &concept(
                    "type: controlled-category\nrequired: true\nconstraints: {categoryScheme: 'urn:example:category-scheme', schemeVersion: '7', maximumBytes: 32, codelist: 'codelists/categories.yaml'}"
                ),
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
            "type: time-bucket\nrequired: true\nconstraints: {bucketScheme: 'urn:example:bucket-scheme', schemeVersion: '1'}",
        );
        let date_bucket = concept(
            "type: date-bucket\nrequired: true\nconstraints: {bucketScheme: 'urn:example:bucket-scheme', schemeVersion: '1'}",
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
            "type: audience-scoped-entity-reference\nrequired: true\nconstraints: {maximumBytes: 160}",
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
            "type: entity-reference-list\nrequired: true\nconstraints: {minimumItems: 1, maximumItems: 2, unique: true}",
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
        let schema = ReviewedSchema::compile(
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
            "type: reviewed-structured-value\nrequired: true\nconstraints: {schema: 'urn:example:structured', maximumSerializedBytes: 512}",
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
        // A closed schema refuses a key it never declared, naming the key.
        assert_eq!(
            validate_value(
                &structured,
                &DerivedValue::Json(
                    json!({"form":"reviewed-structured-value","schema":schema_id,"fields":{"status":"A","effective_date":"2026-02-28","observed_at":"2026-02-28T12:00:00Z","note":"a value the gate must not reprint"}})
                ),
                &projection(),
                &codelists,
                &schemas,
            ),
            Err(KernelError::UndeclaredOutputProperty("note".to_owned()))
        );
        // A schema that predates the closed-authoring rule still declares its
        // property set, so the same key is refused there too: the gate, not the
        // document, closes the form.
        let open_schema = ReviewedSchema::compile(
            "schemas/open-structured.schema.yaml",
            &json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": schema_id,
                "type": "object",
                "required": ["status", "effective_date", "observed_at"],
                "properties": {
                    "status": {"type": "string", "enum": ["A"]},
                    "effective_date": {"type": "string", "format": "date"},
                    "observed_at": {"type": "string", "format": "date-time"}
                }
            }),
        )
        .expect("open schema compiles");
        let open_schemas = BTreeMap::from([(schema_id.to_owned(), open_schema)]);
        assert_eq!(
            validate_value(
                &structured,
                &DerivedValue::Json(
                    json!({"form":"reviewed-structured-value","schema":schema_id,"fields":{"status":"A","effective_date":"2026-02-28","observed_at":"2026-02-28T12:00:00Z","undeclared_member": 1}})
                ),
                &projection(),
                &codelists,
                &open_schemas,
            ),
            Err(KernelError::UndeclaredOutputProperty(
                "undeclared_member".to_owned()
            ))
        );
        // A top level that declares no property set at all has no known set to
        // check against, so only the compiled validation applies.
        let setless_schema = ReviewedSchema::compile(
            "schemas/setless-structured.schema.yaml",
            &json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": schema_id
            }),
        )
        .expect("setless schema compiles");
        let setless_schemas = BTreeMap::from([(schema_id.to_owned(), setless_schema)]);
        assert!(
            validate_value(
                &structured,
                &DerivedValue::Json(json!({"form":"reviewed-structured-value","schema":schema_id,"fields":{"anything":"passes the compiled form"}})),
                &projection(),
                &codelists,
                &setless_schemas,
            )
            .is_ok(),
            "a schema with no known property set is not closed by the gate"
        );
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
            source_valid_until: None,
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

    #[test]
    fn verified_source_deadline_caps_issuance_and_refuses_an_expired_cap() {
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
        let construction = |issued_at, source_valid_until| EvidenceConstruction {
            evidence_id: "urn:ulid:01K1EXAMPLE0000000000000000",
            purpose: &requirement.purposes[0],
            scope: EvidenceScope::AudienceScoped {
                audience: AUDIENCE,
                request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
            },
            issued_at,
            observed_at: "2026-08-02T00:00:00Z".parse().expect("time"),
            source_valid_until,
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
        let capped = kernel
            .construct_evidence(
                &requirement.id,
                values.clone(),
                construction(
                    "2026-08-02T00:00:01.100Z".parse().expect("time"),
                    Some("2026-08-02T00:00:02.900Z".parse().expect("time")),
                ),
            )
            .expect("a source deadline in a later emitted second caps local validity");
        assert_eq!(capped.issued_at, "2026-08-02T00:00:01Z");
        assert_eq!(capped.valid_until, "2026-08-02T00:00:02Z");
        assert_eq!(
            kernel.construct_evidence(
                &requirement.id,
                values,
                construction(
                    "2026-08-02T00:00:01.100Z".parse().expect("time"),
                    Some("2026-08-02T00:00:01.900Z".parse().expect("time")),
                ),
            ),
            Err(KernelError::Evidence),
            "fractional instants in one emitted second cannot form a valid assertion interval"
        );
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
                    source_valid_until: None,
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
            "type: audience-scoped-entity-reference\nrequired: true\nconstraints: {maximumBytes: 160}",
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
        assert_eq!(forms.len(), 12, "all Version 1 forms remain covered");
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
                &concept(
                    "type: controlled-code\nrequired: true\nconstraints: {codelist: oversized, codelistVersion: '1', maximumBytes: 8192}"
                ),
                &DerivedValue::Json(Value::String(oversized)),
                &projection(),
                &BTreeMap::from([("oversized".to_owned(), oversized_codelist)]),
                &BTreeMap::new(),
            ),
            Err(KernelError::Output),
            "per-value-size-plus-one"
        );

        let aggregate_schema_id = "urn:example:fixture:schema:aggregate:v1";
        let aggregate_schema = ReviewedSchema::compile(
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
                    "type: reviewed-structured-value\nrequired: false\nconstraints: {{schema: '{aggregate_schema_id}', maximumSerializedBytes: 8192}}"
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
                "minimum_bytes" => "minimumBytes",
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
                    source_valid_until: None,
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
            "handle: example-concept\nuri: urn:example:concept\n{body}\n"
        ))
        .expect("concept parses")
    }

    #[test]
    fn bounded_identifier_requires_exact_prefix_ascii_suffix_and_byte_bounds() {
        let identifier = concept(
            "type: bounded-identifier\nrequired: true\nconstraints: {prefix: 'urn:example:report:', minimumBytes: 20, maximumBytes: 32}",
        );
        let accepted = DerivedValue::Json(json!("urn:example:report:A-01"));
        assert_eq!(
            validate_value(
                &identifier,
                &accepted,
                &projection(),
                &BTreeMap::new(),
                &BTreeMap::new()
            ),
            Ok(PublicValue::String("urn:example:report:A-01".to_owned()))
        );
        for rejected in [
            json!("urn:example:other:A-01"),
            json!("urn:example:report:"),
            json!("urn:example:report:/A"),
            json!("urn:example:report:A/B"),
            json!("urn:example:report:A B"),
            json!("urn:example:report:é"),
            json!("urn:example:report:ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            json!(12),
        ] {
            assert_eq!(
                validate_value(
                    &identifier,
                    &DerivedValue::Json(rejected),
                    &projection(),
                    &BTreeMap::new(),
                    &BTreeMap::new()
                ),
                Err(KernelError::Output)
            );
        }
    }

    fn observed_for_case(fixture: &Value, test_case: &Value) -> DateTime<Utc> {
        let local_date = test_case
            .get("legalLocalDate")
            .or_else(|| {
                fixture
                    .get("common")
                    .and_then(|common| common.get("legalLocalDate"))
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
        refresh_package_envelope(temporary.path());
        make_read_only(temporary.path());
        temporary
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

    /// Republish a copied test package after its intended authored inputs change.
    /// Tests that deliberately corrupt a package do not use this helper.
    fn refresh_package_envelope(root: &Path) {
        fs::remove_file(root.join(registry_platform_config::SUM_FILE))
            .expect("prior package sum file is removed");
        registry_platform_config::write_sum_file(
            root,
            None,
            &crate::bundle::evidence_package_limits(),
            "evidencectl package",
        )
        .expect("mutated test package is republished");
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
