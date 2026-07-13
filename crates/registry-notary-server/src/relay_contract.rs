// SPDX-License-Identifier: Apache-2.0
//! Independent Notary validation of Relay's canonical public contract.
//!
//! These types are a closed verification boundary, not a second compiler
//! model. Relay remains the contract producer. Notary decodes the authenticated
//! compiler output and checks only the semantics it must understand before it
//! can become ready or make registry-backed source requests.

use std::collections::{BTreeMap, BTreeSet};

use registry_notary_core::RelayOutputContract;
use registry_platform_httputil::destination::MAX_SERVICE_HOP_OPERATION_TIMEOUT;
use serde::Deserialize;

const CONTRACT_SCHEMA: &str = "registry.relay.consultation-contract.v1";
const CONTRACT_VERSION: &str = "1";
const MAX_ID_BYTES: usize = 96;
const MAX_INPUTS: usize = 16;
const MAX_SELECTORS: usize = 8;
const MAX_INPUT_BYTES: u32 = 4_096;
const MAX_INPUT_PATTERN_BYTES: usize = 1_024;
const MAX_OUTPUTS: usize = 64;
const MAX_OUTPUT_STRING_BYTES: u32 = 64 * 1_024;
const MAX_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_SOURCE_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_SCHEMA_FIELDS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayPublicContract {
    schema: String,
    id: String,
    version: String,
    spec: ContractSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractSpec {
    subject: Subject,
    inputs: BTreeMap<String, Input>,
    integration_pack: ArtifactReference,
    acquisition: Acquisition,
    source_provenance: SourceProvenance,
    output: BTreeMap<String, Output>,
    authorization: Authorization,
    bounds: Bounds,
    public_behavior: PublicBehavior,
    runtime: RuntimeRequirements,
    #[serde(default)]
    materialization: Option<Materialization>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    mode: SubjectMode,
    selector_provenance: SelectorProvenance,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubjectMode {
    SingleSubject,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SelectorProvenance {
    WorkloadSelected,
    TrustedNotaryAssertion { assertion_contract: HashReference },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HashReference {
    id: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReference {
    id: String,
    version: String,
    hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputRole {
    Selector,
    Parameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputScalarType {
    String,
    Boolean,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputTypeMember {
    String,
    Boolean,
    Integer,
    Null,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InputSchemaType {
    Scalar(InputScalarType),
    Nullable(Vec<InputTypeMember>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StringFormat {
    Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Canonicalization {
    Identity,
    AsciiLowercase,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    role: InputRole,
    #[serde(rename = "type")]
    schema_type: InputSchemaType,
    #[serde(default)]
    format: Option<StringFormat>,
    #[serde(rename = "maxLength", default)]
    max_length: Option<u32>,
    #[serde(rename = "minLength", default)]
    min_length: Option<u32>,
    #[serde(rename = "x-registry-max-bytes", default)]
    max_bytes: Option<u32>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(rename = "x-registry-canonicalization")]
    canonicalization: Canonicalization,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
    #[serde(rename = "enum", default)]
    allowed_values: Vec<serde_json::Value>,
    #[serde(rename = "const", default)]
    constant: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcquisitionClass {
    SourceProjectedExact,
    BoundedFullRecord,
    MaterializedSnapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acquisition {
    class: AcquisitionClass,
    fields: BTreeMap<String, ResponseSchema>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseSchema {
    ScriptBody,
    Object {
        nullable: bool,
        reject_unknown_fields: bool,
        fields: BTreeMap<String, ResponseField>,
    },
    Array {
        nullable: bool,
        max_items: u16,
        items: Box<ResponseSchema>,
    },
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseField {
    required: bool,
    schema: Box<ResponseSchema>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceProvenance {
    source_observed_at: SourceObservedAt,
    source_revision: SourceRevision,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SourceObservedAt {
    Absent,
    AcquiredRfc3339 { field: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SourceRevision {
    Absent,
    AcquiredString { field: String, max_bytes: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutputType {
    String,
    Boolean,
    Integer,
    Date,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    #[serde(rename = "type")]
    output_type: OutputType,
    nullable: bool,
    #[serde(default)]
    max_bytes: Option<u32>,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    workload: String,
    required_scope: String,
    purposes: Vec<String>,
    legal_basis: String,
    policy: Policy,
    consent: Consent,
    mandatory_obligations: Vec<Never>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    id: String,
    hash: String,
    decision_cache: PolicyCache,
    max_decision_age_ms: u32,
    unavailable: Unavailable,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyCache {
    Disabled,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Unavailable {
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    required: bool,
    #[serde(default)]
    verifier: Option<HashReference>,
    #[serde(default)]
    max_age_ms: Option<u32>,
    #[serde(default)]
    revocation: Option<ConsentRevocation>,
    #[serde(default)]
    unavailable: Option<Unavailable>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConsentRevocation {
    OnlineRequired,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Never {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    max_source_matches: u8,
    max_disclosed_records: u8,
    max_data_exchanges: u8,
    max_credential_exchanges: u8,
    max_data_destinations: u8,
    max_source_bytes: u64,
    timeout_ms: u32,
    max_in_flight: u16,
    quota_per_minute: u32,
    quota_burst: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Match,
    NoMatch,
    Ambiguous,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBehavior {
    outcomes: Vec<Outcome>,
    denial_code: String,
    denial_timing_profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRequirements {
    platform_profile: String,
    source_capability: SourceCapability,
    script_abi: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceCapability {
    Http,
    Script,
    Snapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Materialization {
    max_snapshot_age_ms: u64,
    stale_behavior: MaterializationStaleBehavior,
    footprint: MaterializationFootprint,
    refresh_class: MaterializationRefreshClass,
    snapshot_retention_generations: u16,
    immutable_generation: bool,
    digest_bound_active_pointer: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaterializationStaleBehavior {
    Unavailable,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaterializationRefreshClass {
    OperatorTriggered,
    Scheduled,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializationFootprint {
    fields: Vec<String>,
    max_source_records: u64,
    max_source_bytes: u64,
    max_data_exchanges: u8,
    max_credential_exchanges: u8,
    max_data_destinations: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedContractSemantics {
    pub(crate) acquisition_class: VerifiedAcquisitionClass,
    pub(crate) integration_id: Box<str>,
    pub(crate) integration_revision: i64,
    pub(crate) source_observed_at: VerifiedSourceField,
    pub(crate) source_revision: VerifiedSourceField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifiedAcquisitionClass {
    SourceProjectedExact,
    BoundedFullRecord,
    MaterializedSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiedSourceField {
    Absent,
    Required,
}

pub(crate) fn verify_contract(
    contract: RelayPublicContract,
    profile_id: &str,
    workload_client_id: &str,
    purpose: &str,
    input_names: &[String],
    expected_outputs: &BTreeMap<String, RelayOutputContract>,
) -> Result<VerifiedContractSemantics, ()> {
    if contract.schema != CONTRACT_SCHEMA
        || contract.version != CONTRACT_VERSION
        || contract.id != profile_id
        || !stable_id(&contract.id)
    {
        return Err(());
    }
    let spec = contract.spec;
    verify_subject(&spec.subject)?;
    verify_inputs(&spec.inputs, input_names)?;
    verify_outputs(&spec.output, expected_outputs)?;
    verify_authorization(&spec.authorization, workload_client_id, purpose)?;
    verify_behavior(&spec.public_behavior)?;
    verify_runtime(&spec.runtime, spec.acquisition.class)?;
    verify_bounds(&spec.bounds, spec.acquisition.class)?;
    verify_response_schemas(&spec.acquisition.fields)?;
    let integration_revision = positive_revision(&spec.integration_pack.version)?;
    if !stable_id(&spec.integration_pack.id) || !sha256_uri(&spec.integration_pack.hash) {
        return Err(());
    }
    let source_observed_at = verify_observed_at(
        &spec.source_provenance.source_observed_at,
        &spec.acquisition.fields,
    )?;
    let source_revision = verify_source_revision(
        &spec.source_provenance.source_revision,
        &spec.acquisition.fields,
    )?;
    verify_materialization(spec.acquisition.class, spec.materialization.as_ref())?;

    Ok(VerifiedContractSemantics {
        acquisition_class: match spec.acquisition.class {
            AcquisitionClass::SourceProjectedExact => {
                VerifiedAcquisitionClass::SourceProjectedExact
            }
            AcquisitionClass::BoundedFullRecord => VerifiedAcquisitionClass::BoundedFullRecord,
            AcquisitionClass::MaterializedSnapshot => {
                VerifiedAcquisitionClass::MaterializedSnapshot
            }
        },
        integration_id: spec.integration_pack.id.into_boxed_str(),
        integration_revision,
        source_observed_at,
        source_revision,
    })
}

fn verify_subject(subject: &Subject) -> Result<(), ()> {
    if !matches!(subject.mode, SubjectMode::SingleSubject) {
        return Err(());
    }
    match &subject.selector_provenance {
        SelectorProvenance::WorkloadSelected => Ok(()),
        SelectorProvenance::TrustedNotaryAssertion { assertion_contract } => {
            if stable_id(&assertion_contract.id) && sha256_uri(&assertion_contract.hash) {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

fn verify_inputs(inputs: &BTreeMap<String, Input>, expected_names: &[String]) -> Result<(), ()> {
    if !(1..=MAX_INPUTS).contains(&inputs.len())
        || inputs.keys().ne(expected_names.iter())
        || inputs.keys().any(|name| !stable_id(name))
    {
        return Err(());
    }
    let selector_count = inputs
        .values()
        .filter(|input| input.role == InputRole::Selector)
        .count();
    if !(1..=MAX_SELECTORS).contains(&selector_count) {
        return Err(());
    }
    let mut aggregate_bytes = 0_u32;
    for input in inputs.values() {
        let (scalar, nullable) = resolved_input_type(&input.schema_type)?;
        if input.role == InputRole::Selector && nullable {
            return Err(());
        }
        let bytes = match scalar {
            InputScalarType::String => {
                let max_length = input.max_length.filter(|value| *value > 0).ok_or(())?;
                let max_bytes = input.max_bytes.filter(|value| *value > 0).ok_or(())?;
                if input.min_length.is_some_and(|minimum| minimum > max_length)
                    || input.pattern.as_ref().is_some_and(|pattern| {
                        pattern.is_empty() || pattern.len() > MAX_INPUT_PATTERN_BYTES
                    })
                    || input.minimum.is_some()
                    || input.maximum.is_some()
                    || input
                        .format
                        .is_some_and(|format| format != StringFormat::Date)
                {
                    return Err(());
                }
                max_bytes
            }
            InputScalarType::Boolean => {
                if input.format.is_some()
                    || input.max_length.is_some()
                    || input.min_length.is_some()
                    || input.max_bytes.is_some()
                    || input.pattern.is_some()
                    || input.minimum.is_some()
                    || input.maximum.is_some()
                {
                    return Err(());
                }
                5
            }
            InputScalarType::Integer => {
                let minimum = input.minimum.ok_or(())?;
                let maximum = input.maximum.ok_or(())?;
                if minimum > maximum
                    || minimum < -MAX_JSON_INTEGER
                    || maximum > MAX_JSON_INTEGER
                    || input.format.is_some()
                    || input.max_length.is_some()
                    || input.min_length.is_some()
                    || input.max_bytes.is_some()
                    || input.pattern.is_some()
                {
                    return Err(());
                }
                u32::try_from(minimum.to_string().len().max(maximum.to_string().len()))
                    .map_err(|_| ())?
            }
        };
        verify_allowed_values(input, scalar, nullable)?;
        let _ = input.canonicalization;
        aggregate_bytes = aggregate_bytes
            .checked_add(if nullable { bytes.max(4) } else { bytes })
            .ok_or(())?;
    }
    (aggregate_bytes <= MAX_INPUT_BYTES).then_some(()).ok_or(())
}

fn resolved_input_type(schema: &InputSchemaType) -> Result<(InputScalarType, bool), ()> {
    match schema {
        InputSchemaType::Scalar(scalar) => Ok((*scalar, false)),
        InputSchemaType::Nullable(members) if members.len() == 2 => {
            let mut scalar = None;
            let mut has_null = false;
            for member in members {
                match member {
                    InputTypeMember::String => set_once(&mut scalar, InputScalarType::String)?,
                    InputTypeMember::Boolean => set_once(&mut scalar, InputScalarType::Boolean)?,
                    InputTypeMember::Integer => set_once(&mut scalar, InputScalarType::Integer)?,
                    InputTypeMember::Null if !has_null => has_null = true,
                    InputTypeMember::Null => return Err(()),
                }
            }
            match (scalar, has_null) {
                (Some(scalar), true) => Ok((scalar, true)),
                _ => Err(()),
            }
        }
        InputSchemaType::Nullable(_) => Err(()),
    }
}

fn set_once(slot: &mut Option<InputScalarType>, value: InputScalarType) -> Result<(), ()> {
    if slot.replace(value).is_some() {
        Err(())
    } else {
        Ok(())
    }
}

fn verify_allowed_values(input: &Input, scalar: InputScalarType, nullable: bool) -> Result<(), ()> {
    for value in input.allowed_values.iter().chain(input.constant.iter()) {
        if value.is_null() && nullable {
            continue;
        }
        let valid = match scalar {
            InputScalarType::String => value.as_str().is_some_and(|value| {
                input.max_length.is_some_and(|maximum| {
                    u32::try_from(value.chars().count()).is_ok_and(|length| length <= maximum)
                })
            }),
            InputScalarType::Boolean => value.is_boolean(),
            InputScalarType::Integer => value.as_i64().is_some_and(|value| {
                input.minimum.is_some_and(|minimum| value >= minimum)
                    && input.maximum.is_some_and(|maximum| value <= maximum)
            }),
        };
        if !valid {
            return Err(());
        }
    }
    Ok(())
}

fn verify_outputs(
    outputs: &BTreeMap<String, Output>,
    expected: &BTreeMap<String, RelayOutputContract>,
) -> Result<(), ()> {
    if outputs.len() > MAX_OUTPUTS || outputs.keys().ne(expected.keys()) {
        return Err(());
    }
    for (name, output) in outputs {
        if !stable_id(name) || matches!(name.as_str(), "matched" | "outcome") {
            return Err(());
        }
        let valid = match (output.output_type, &expected[name]) {
            (
                OutputType::String,
                RelayOutputContract::String {
                    nullable,
                    max_bytes,
                },
            ) => {
                output.nullable == *nullable
                    && output.max_bytes == Some(*max_bytes)
                    && (1..=MAX_OUTPUT_STRING_BYTES).contains(max_bytes)
                    && output.minimum.is_none()
                    && output.maximum.is_none()
            }
            (OutputType::Date, RelayOutputContract::Date { nullable }) => {
                output.nullable == *nullable
                    && output.max_bytes.is_none_or(|bytes| bytes == 10)
                    && output.minimum.is_none()
                    && output.maximum.is_none()
            }
            (OutputType::Boolean, RelayOutputContract::Boolean { nullable }) => {
                output.nullable == *nullable
                    && output.max_bytes.is_none()
                    && output.minimum.is_none()
                    && output.maximum.is_none()
            }
            (
                OutputType::Integer,
                RelayOutputContract::Integer {
                    nullable,
                    minimum,
                    maximum,
                },
            ) => {
                output.nullable == *nullable
                    && output.minimum == Some(*minimum)
                    && output.maximum == Some(*maximum)
                    && minimum <= maximum
                    && *minimum >= -MAX_JSON_INTEGER
                    && *maximum <= MAX_JSON_INTEGER
                    && output.max_bytes.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err(());
        }
    }
    Ok(())
}

fn verify_authorization(
    authorization: &Authorization,
    workload_client_id: &str,
    purpose: &str,
) -> Result<(), ()> {
    if authorization.workload != workload_client_id
        || authorization.purposes.as_slice() != [purpose]
        || authorization.required_scope.is_empty()
        || authorization.required_scope.len() > 256
        || authorization.legal_basis.is_empty()
        || authorization.legal_basis.len() > 96
        || !stable_id(&authorization.policy.id)
        || !sha256_uri(&authorization.policy.hash)
        || authorization.policy.max_decision_age_ms == 0
        || authorization.consent.required
        || authorization.consent.verifier.is_some()
        || authorization.consent.max_age_ms.is_some()
        || authorization.consent.revocation.is_some()
        || authorization.consent.unavailable.is_some()
        || !authorization.mandatory_obligations.is_empty()
    {
        return Err(());
    }
    let _ = (
        &authorization.policy.decision_cache,
        &authorization.policy.unavailable,
    );
    Ok(())
}

fn verify_behavior(behavior: &PublicBehavior) -> Result<(), ()> {
    let outcomes = behavior.outcomes.iter().copied().collect::<BTreeSet<_>>();
    (behavior.outcomes.len() == 3
        && outcomes == BTreeSet::from([Outcome::Match, Outcome::NoMatch, Outcome::Ambiguous])
        && behavior.denial_code == "consultation.denied"
        && behavior.denial_timing_profile == "measured-uniform-v1")
        .then_some(())
        .ok_or(())
}

fn verify_runtime(runtime: &RuntimeRequirements, acquisition: AcquisitionClass) -> Result<(), ()> {
    if runtime.platform_profile != "registry-stack.consultation.v1" {
        return Err(());
    }
    match (
        runtime.source_capability,
        runtime.script_abi.as_deref(),
        acquisition,
    ) {
        (
            SourceCapability::Script,
            Some("xw.v1"),
            AcquisitionClass::SourceProjectedExact | AcquisitionClass::BoundedFullRecord,
        )
        | (
            SourceCapability::Http,
            None,
            AcquisitionClass::SourceProjectedExact | AcquisitionClass::BoundedFullRecord,
        )
        | (SourceCapability::Snapshot, None, AcquisitionClass::MaterializedSnapshot) => Ok(()),
        _ => Err(()),
    }
}

fn verify_bounds(bounds: &Bounds, class: AcquisitionClass) -> Result<(), ()> {
    let transport = match class {
        AcquisitionClass::SourceProjectedExact | AcquisitionClass::BoundedFullRecord => {
            (1..=16).contains(&bounds.max_data_exchanges)
                && bounds.max_credential_exchanges <= 1
                && bounds.max_data_destinations == 1
        }
        AcquisitionClass::MaterializedSnapshot => {
            bounds.max_data_exchanges == 0
                && bounds.max_credential_exchanges == 0
                && bounds.max_data_destinations == 0
        }
    };
    let compatible_timeout =
        u128::from(bounds.timeout_ms) <= MAX_SERVICE_HOP_OPERATION_TIMEOUT.as_millis();
    ((1..=2).contains(&bounds.max_source_matches)
        && bounds.max_disclosed_records == 1
        && transport
        && (1..=MAX_SOURCE_BYTES).contains(&bounds.max_source_bytes)
        && bounds.timeout_ms > 0
        && compatible_timeout
        && (1..=64).contains(&bounds.max_in_flight)
        && bounds.quota_per_minute > 0
        && bounds.quota_burst > 0
        && u32::from(bounds.quota_burst) <= bounds.quota_per_minute)
        .then_some(())
        .ok_or(())
}

fn verify_response_schemas(fields: &BTreeMap<String, ResponseSchema>) -> Result<(), ()> {
    if fields.is_empty() || fields.len() > MAX_SCHEMA_FIELDS {
        return Err(());
    }
    let mut nodes = 0_usize;
    for (name, schema) in fields {
        if !bounded_name(name) {
            return Err(());
        }
        verify_response_schema(schema, 1, &mut nodes)?;
    }
    Ok(())
}

fn verify_response_schema(
    schema: &ResponseSchema,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ()> {
    *nodes = nodes.checked_add(1).ok_or(())?;
    if depth > MAX_SCHEMA_DEPTH || *nodes > MAX_SCHEMA_FIELDS {
        return Err(());
    }
    match schema {
        ResponseSchema::ScriptBody => Ok(()),
        ResponseSchema::Object {
            nullable,
            reject_unknown_fields,
            fields,
        } => {
            let _ = (nullable, reject_unknown_fields);
            if fields.is_empty() || fields.len() > 32 {
                return Err(());
            }
            for (name, field) in fields {
                if !bounded_name(name) {
                    return Err(());
                }
                let _ = field.required;
                verify_response_schema(&field.schema, depth + 1, nodes)?;
            }
            Ok(())
        }
        ResponseSchema::Array {
            nullable,
            max_items,
            items,
        } => {
            let _ = nullable;
            if *max_items == 0 || *max_items > 256 {
                return Err(());
            }
            verify_response_schema(items, depth + 1, nodes)
        }
        ResponseSchema::String {
            nullable,
            max_bytes,
        } => {
            let _ = nullable;
            (1..=MAX_OUTPUT_STRING_BYTES)
                .contains(max_bytes)
                .then_some(())
                .ok_or(())
        }
        ResponseSchema::Boolean { nullable } => {
            let _ = nullable;
            Ok(())
        }
        ResponseSchema::Integer {
            nullable,
            minimum,
            maximum,
        }
        | ResponseSchema::Number {
            nullable,
            minimum,
            maximum,
        } => {
            let _ = nullable;
            (*minimum <= *maximum && *minimum >= -MAX_JSON_INTEGER && *maximum <= MAX_JSON_INTEGER)
                .then_some(())
                .ok_or(())
        }
    }
}

fn verify_observed_at(
    observed: &SourceObservedAt,
    fields: &BTreeMap<String, ResponseSchema>,
) -> Result<VerifiedSourceField, ()> {
    match observed {
        SourceObservedAt::Absent => Ok(VerifiedSourceField::Absent),
        SourceObservedAt::AcquiredRfc3339 { field } => match fields.get(field) {
            Some(ResponseSchema::String {
                nullable: false,
                max_bytes,
            }) if *max_bytes <= 64 => Ok(VerifiedSourceField::Required),
            _ => Err(()),
        },
    }
}

fn verify_source_revision(
    revision: &SourceRevision,
    fields: &BTreeMap<String, ResponseSchema>,
) -> Result<VerifiedSourceField, ()> {
    match revision {
        SourceRevision::Absent => Ok(VerifiedSourceField::Absent),
        SourceRevision::AcquiredString { field, max_bytes } => match fields.get(field) {
            Some(ResponseSchema::String {
                nullable: false,
                max_bytes: field_max,
            }) if *max_bytes > 0 && *max_bytes <= 128 && u32::from(*max_bytes) == *field_max => {
                Ok(VerifiedSourceField::Required)
            }
            _ => Err(()),
        },
    }
}

fn verify_materialization(
    class: AcquisitionClass,
    materialization: Option<&Materialization>,
) -> Result<(), ()> {
    match (class, materialization) {
        (AcquisitionClass::MaterializedSnapshot, Some(materialization)) => {
            let _ = (
                &materialization.stale_behavior,
                &materialization.refresh_class,
            );
            (materialization.max_snapshot_age_ms > 0
                && !materialization.footprint.fields.is_empty()
                && materialization
                    .footprint
                    .fields
                    .iter()
                    .all(|field| bounded_name(field))
                && materialization.footprint.max_source_records > 0
                && (1..=MAX_SOURCE_BYTES).contains(&materialization.footprint.max_source_bytes)
                && (1..=16).contains(&materialization.footprint.max_data_exchanges)
                && materialization.footprint.max_credential_exchanges <= 1
                && materialization.footprint.max_data_destinations == 1
                && materialization.snapshot_retention_generations > 0
                && materialization.immutable_generation
                && materialization.digest_bound_active_pointer)
                .then_some(())
                .ok_or(())
        }
        (AcquisitionClass::SourceProjectedExact | AcquisitionClass::BoundedFullRecord, None) => {
            Ok(())
        }
        _ => Err(()),
    }
}

fn positive_revision(value: &str) -> Result<i64, ()> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_JSON_INTEGER)
        .ok_or(())
}

fn stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn bounded_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn sha256_uri(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
