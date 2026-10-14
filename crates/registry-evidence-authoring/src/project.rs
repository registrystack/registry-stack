//! One normalized Evidence project. This module only transforms supplied values.
use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{
    ApiVersion, BoundedU64, Decoded, EnvelopeRule, FormatSpec, LocalId, Report, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    finding::{FieldPath, Finding},
    formats::{decode_authored, findings_report},
};

pub const MAX_VALIDITY_SECONDS: u64 = 31_536_000;

pub const PROJECT_FILE: &str = "evidence.yaml";
pub const PROJECT_API_VERSION: &str = "id.registrystack.org/formats/evidence/project/v1alpha1";
pub const PROJECT_KIND: &str = "EvidenceProject";
pub const PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/project/project.v1alpha1.schema.json";
pub const PROJECT: FormatSpec<'static> = FormatSpec {
    kind: PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProject {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub id: LocalId,
    pub selector_profiles: BTreeMap<LocalId, SelectorProfile>,
    pub functions: Vec<Function>,
    pub sources: BTreeMap<LocalId, Source>,
    pub assertion_definitions: BTreeMap<LocalId, AssertionDefinition>,
    /// Package opt-in ceilings. Operators must separately enable these acquisitions.
    #[serde(default, skip_serializing_if = "empty_capabilities")]
    pub acquisition_capabilities: UniqueList<AcquisitionCapability>,
    /// Maximum assertions released together in one holder-bound batch; omission means one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_holder_bound_batch_size: Option<BoundedU64<1, 16>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionCapability {
    SearchThenFetchSet,
    SourceBatch,
}

pub fn empty_capabilities(value: &UniqueList<AcquisitionCapability>) -> bool {
    value.is_empty()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorProfile {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub maximum_aggregate_bytes: BoundedU64<1, 8192>,
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-passthrough" = "Reviewed bounded selector field schemas, normalized by the Evidence compiler and checked by the kernel.")))]
    pub fields: BTreeMap<LocalId, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Function {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub id: LocalId,
    pub interface: FunctionInterface,
    pub source: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FunctionInterface {
    #[serde(rename = "source-prepare/v1")]
    SourcePrepare,
    #[serde(rename = "source-extract/v1")]
    SourceExtract,
    #[serde(rename = "assertion-derive/v1")]
    AssertionDerive,
}
impl FunctionInterface {
    pub const fn entry_point(self) -> (&'static str, &'static [usize]) {
        match self {
            Self::SourcePrepare => ("prepare", &[2]),
            Self::SourceExtract => ("extract", &[2, 3]),
            Self::AssertionDerive => ("derive", &[3]),
        }
    }
    pub const fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::SourcePrepare => &["bounded-request-parts"],
            Self::SourceExtract => &["lookup-outcome", "private-facts"],
            Self::AssertionDerive => &["declared-outputs"],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionCall {
    pub function: LocalId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-passthrough" = "Literal reviewed Function parameter bindings, checked at the named Function call site.")))]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_inputs: Vec<Value>,
}

/// Source preparation and extraction share the Source's declared adapter
/// parameters and minimized selector inputs. Call sites cannot override them.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SourceFunctionRef {
    pub function: LocalId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssertionDefinition {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub question: String,
    pub semantics: Semantics,
    pub purpose: String,
    pub grant_ceiling: GrantCeiling,
    pub subjects: Vec<Subject>,
    pub acquisition: Acquisition,
    pub derive: FunctionCall,
    #[cfg_attr(feature = "schema", schemars(extend("minProperties" = 1, "maxProperties" = 32)))]
    pub outputs: BTreeMap<LocalId, Output>,
    pub validity_seconds: BoundedU64<1, MAX_VALIDITY_SECONDS>,
    pub subject_binding: BindingMode,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub representations: UniqueList<Representation>,
    #[serde(default = "utc")]
    pub observation_timezone: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixtures: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_guard: Option<Value>,
    #[serde(default = "collapse_unresolved")]
    pub existence_disclosure: String,
}
fn utc() -> String {
    "UTC".to_owned()
}
fn collapse_unresolved() -> String {
    "collapse-unresolved".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Semantics {
    pub requirement: String,
    pub kind: String,
    pub evidence_type: String,
    pub reference_frameworks: UniqueList<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantCeiling {
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub authorities: UniqueList<String>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub actor_kinds: UniqueList<String>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub value_origins: UniqueList<String>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub audiences: UniqueList<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub role: LocalId,
    pub selectors: UniqueList<LocalId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Representation {
    SignedJws,
    SdJwtVc,
    UnsignedJson,
    SdJwtVcBatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    AudienceScoped,
    HolderBound,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Acquisition {
    Single {
        source: LocalId,
    },
    SearchThenFetch {
        search: LocalId,
        fetch: LocalId,
    },
    #[serde(rename_all = "camelCase")]
    SearchThenFetchSet {
        search: LocalId,
        fetch: Vec<FetchMember>,
        maximum_acquisition_milliseconds: BoundedU64<1, 30_000>,
    },
}
registry_platform_yaml::tagged_union!(Acquisition);
impl Serialize for Acquisition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let external = Self::serialize(self, serde_json::value::Serializer)
            .map_err(serde::ser::Error::custom)?;
        let Value::Object(variants) = external else {
            return Err(serde::ser::Error::custom(
                "acquisition variant must be a mapping",
            ));
        };
        let Some((tag, Value::Object(mut body))) = variants.into_iter().next() else {
            return Err(serde::ser::Error::custom(
                "acquisition body must be a mapping",
            ));
        };
        body.insert("type".to_owned(), json!(tag));
        body.serialize(serializer)
    }
}
impl Acquisition {
    pub fn source_ids(&self) -> Vec<&LocalId> {
        match self {
            Self::Single { source } => vec![source],
            Self::SearchThenFetch { search, fetch } => vec![search, fetch],
            Self::SearchThenFetchSet { search, fetch, .. } => std::iter::once(search)
                .chain(fetch.iter().map(|member| &member.source))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchMember {
    pub source: LocalId,
    pub fact_inputs: UniqueList<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Output {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub concept: String,
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = -9_007_199_254_740_991_i64, max = 9_007_199_254_740_991_i64)))]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(range(min = -9_007_199_254_740_991_i64, max = 9_007_199_254_740_991_i64)))]
    pub maximum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_bytes: Option<BoundedU64<1, 1024>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_bytes: Option<BoundedU64<1, 1024>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_items: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_items: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_serialized_bytes: Option<BoundedU64<1, 65536>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub source_type: SourceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<LocalId>,
    pub acquisition_posture: String,
    #[serde(default)]
    pub selectors: Vec<SourceSelector>,
    pub request: Value,
    pub response: SourceResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare: Option<SourceFunctionRef>,
    pub extract: SourceFunctionRef,
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-passthrough" = "Reviewed bounded private fact schemas, normalized by the Evidence compiler and checked by the kernel.")))]
    pub facts: BTreeMap<LocalId, Value>,
    pub limits: SourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_parameters: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    pub adapter_parameters_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_limits: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<SourceBatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract_profile: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_extract_age_seconds: Option<BoundedU64<1, 2_592_000>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_problem: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_revision: Option<String>,
    #[serde(default)]
    pub forward_access_attribution: bool,
}

/// A bounded physical Source call serving independent slotted logical lookups.
/// The same reviewed Function interfaces are used with their batch call-site types.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBatch {
    pub maximum_items: BoundedU64<1, 16>,
    pub prepare: SourceFunctionRef,
    pub extract: SourceFunctionRef,
    pub response: BatchResponse,
}

/// The batch response uses the Source's byte and transport ceilings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BatchResponse {
    pub projection: Vec<String>,
    pub shape: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SourceType {
    HttpJson,
    SqliteExtract,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SourceSelector {
    pub role: LocalId,
    pub profiles: UniqueList<LocalId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceResponse {
    pub projection: Vec<String>,
    pub shape: Value,
    pub maximum_bytes: BoundedU64<1, 1_048_576>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceLimits {
    pub attempt_timeout_milliseconds: BoundedU64<1, 30_000>,
    pub maximum_concurrency: BoundedU64<1, 256>,
}

/// Typed reader shared by CLI and unsaved editor buffers.
pub fn read_project(file: &str, bytes: &[u8]) -> Result<Decoded<EvidenceProject>, Report> {
    let decoded = decode_authored::<EvidenceProject>(file, bytes, &PROJECT)?;
    let report = findings_report(
        &decoded.document,
        "project",
        validate_project(&decoded.value),
    );
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

pub fn validate_project(project: &EvidenceProject) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut push = |path, code, message| findings.push(Finding::new(path, code, message));
    let functions: BTreeMap<_, _> = project.functions.iter().map(|f| (&f.id, f)).collect();
    if functions.len() != project.functions.len() {
        push(
            FieldPath::root().key("functions"),
            "function-unique",
            "function IDs must be unique",
        );
    }
    if project.assertion_definitions.is_empty() || project.assertion_definitions.len() > 128 {
        push(
            FieldPath::root().key("assertionDefinitions"),
            "definition-count",
            "declare between one and 128 assertion definitions",
        );
    }
    for (index, function) in project.functions.iter().enumerate() {
        if !valid_asset(&function.source, "rhai") {
            push(
                FieldPath::root()
                    .key("functions")
                    .index(index)
                    .key("source"),
                "function-source",
                "name one project-relative .rhai function asset without traversal",
            );
        }
    }
    let mut requirements = BTreeSet::new();
    for (id, definition) in &project.assertion_definitions {
        let at = FieldPath::root()
            .key("assertionDefinitions")
            .map_key(id.to_string());
        if definition.question.trim().is_empty() || definition.question.len() > 1024 {
            push(
                at.clone().key("question"),
                "definition-question",
                "write one bounded human-readable question",
            );
        }
        if !requirements.insert(&definition.semantics.requirement) {
            push(
                at.clone().key("semantics").key("requirement"),
                "requirement-unique",
                "each definition must have a distinct Requirement URI",
            );
        }
        if !absolute_uri(&definition.semantics.requirement)
            || !absolute_uri(&definition.semantics.evidence_type)
            || definition.semantics.reference_frameworks.is_empty()
            || definition
                .semantics
                .reference_frameworks
                .iter()
                .any(|uri| !absolute_uri(uri))
        {
            push(
                at.clone().key("semantics"),
                "semantic-uri",
                "declare absolute Requirement, Evidence Type and reference-framework URIs",
            );
        }
        if !matches!(
            definition.semantics.kind.as_str(),
            "criterion" | "information-requirement" | "constraint"
        ) {
            push(
                at.clone().key("semantics").key("kind"),
                "requirement-kind",
                "kind must be criterion, information-requirement or constraint",
            );
        }
        if definition.grant_ceiling.authorities.is_empty()
            || definition.grant_ceiling.actor_kinds.is_empty()
            || definition.grant_ceiling.value_origins.is_empty()
            || definition.grant_ceiling.audiences.is_empty()
            || definition.representations.is_empty()
        {
            push(at.clone().key("grantCeiling"), "grant-ceiling-empty", "declare complete, nonempty authority, actor, value-origin, audience and representation ceilings");
        }
        if definition.subjects.is_empty() || definition.subjects.len() > 8 {
            push(
                at.clone().key("subjects"),
                "subject-count",
                "declare between one and eight subject roles",
            );
        }
        let mut roles = BTreeSet::new();
        for (index, subject) in definition.subjects.iter().enumerate() {
            if !roles.insert(&subject.role) || subject.selectors.is_empty() {
                push(
                    at.clone().key("subjects").index(index),
                    "subject-selectors",
                    "declare distinct roles and existing selector profiles",
                );
            }
            for (profile_index, profile) in subject.selectors.iter().enumerate() {
                if !project.selector_profiles.contains_key(profile) {
                    push(
                        at.clone()
                            .key("subjects")
                            .index(index)
                            .key("selectors")
                            .index(profile_index),
                        "subject-selectors",
                        "name an existing selector profile",
                    );
                }
            }
        }
        let sources = definition.acquisition.source_ids();
        let references = match &definition.acquisition {
            Acquisition::Single { source } => {
                vec![(at.clone().key("acquisition").key("source"), source)]
            }
            Acquisition::SearchThenFetch { search, fetch } => vec![
                (at.clone().key("acquisition").key("search"), search),
                (at.clone().key("acquisition").key("fetch"), fetch),
            ],
            Acquisition::SearchThenFetchSet { search, fetch, .. } => {
                std::iter::once((at.clone().key("acquisition").key("search"), search))
                    .chain(fetch.iter().enumerate().map(|(index, member)| {
                        (
                            at.clone()
                                .key("acquisition")
                                .key("fetch")
                                .index(index)
                                .key("source"),
                            &member.source,
                        )
                    }))
                    .collect()
            }
        };
        for (path, source) in references {
            if !project.sources.contains_key(source) {
                push(
                    path,
                    "acquisition-source",
                    "acquisition must name an existing Source",
                );
            }
        }
        if sources.iter().collect::<BTreeSet<_>>().len() != sources.len() {
            push(
                at.clone().key("acquisition"),
                "acquisition-source",
                "acquisition must name distinct Sources",
            );
        }
        if functions
            .get(&definition.derive.function)
            .is_none_or(|f| f.interface != FunctionInterface::AssertionDerive)
        {
            push(
                at.clone().key("derive").key("function"),
                "function-interface",
                "derive must name an assertion-derive/v1 Function",
            );
        }
        if definition.outputs.is_empty() || definition.outputs.len() > 32 {
            push(
                at.clone().key("outputs"),
                "output-count",
                "declare between one and 32 public Outputs",
            );
        }
        for (name, output) in &definition.outputs {
            let scalar = output.value_type.trim_end_matches("-list");
            let no_integer = output.minimum.is_none() && output.maximum.is_none();
            let no_identifier = output.prefix.is_none()
                && output.minimum_bytes.is_none()
                && output.maximum_bytes.is_none();
            let no_schema = output.schema.is_none() && output.maximum_serialized_bytes.is_none();
            let relevant = match scalar {
                "boolean" => output.values.is_empty() && no_integer && no_identifier && no_schema,
                "controlled-category" => no_integer && no_identifier && no_schema,
                "bounded-identifier" => output.values.is_empty() && no_integer && no_schema,
                "bounded-integer" => output.values.is_empty() && no_identifier && no_schema,
                "reviewed-structured-value" => {
                    output.values.is_empty() && no_integer && no_identifier
                }
                _ => false,
            };
            let bounded =
                match scalar {
                    "boolean" => {
                        output.values.is_empty()
                            && output.minimum.is_none()
                            && output.maximum.is_none()
                            && output.prefix.is_none()
                            && output.minimum_bytes.is_none()
                            && output.maximum_bytes.is_none()
                            && output.schema.is_none()
                    }
                    "controlled-category" => {
                        !output.values.is_empty()
                            && output.values.len() <= 32
                            && output
                                .values
                                .iter()
                                .all(|value| !value.is_empty() && value.len() <= 64)
                            && output.values.iter().collect::<BTreeSet<_>>().len()
                                == output.values.len()
                    }
                    "bounded-identifier" => {
                        output
                            .prefix
                            .as_ref()
                            .is_some_and(|prefix| !prefix.is_empty())
                            && output
                                .minimum_bytes
                                .zip(output.maximum_bytes)
                                .is_some_and(|(minimum, maximum)| minimum <= maximum)
                    }
                    "bounded-integer" => {
                        output
                            .minimum
                            .zip(output.maximum)
                            .is_some_and(|(minimum, maximum)| {
                                minimum <= maximum
                                    && minimum >= -9_007_199_254_740_991
                                    && maximum <= 9_007_199_254_740_991
                            })
                    }
                    "reviewed-structured-value" => {
                        output.schema.as_ref().is_some_and(|path| {
                            valid_asset(path, "yaml") || valid_asset(path, "json")
                        }) && output.maximum_serialized_bytes.is_some()
                    }
                    _ => false,
                };
            let list = if output.value_type.ends_with("-list") {
                output
                    .minimum_items
                    .zip(output.maximum_items)
                    .is_some_and(|(minimum, maximum)| minimum <= maximum)
            } else {
                output.minimum_items.is_none() && output.maximum_items.is_none()
            };
            if !bounded || !list || !relevant {
                push(
                    at.clone().key("outputs").map_key(name.to_string()),
                    "output-bounds",
                    "declare exactly the finite bounds required by this Output type",
                );
            }
            if !absolute_uri(&output.concept) {
                push(
                    at.clone()
                        .key("outputs")
                        .map_key(name.to_string())
                        .key("concept"),
                    "output-concept",
                    "an Output concept must be an absolute URI",
                );
            }
            if !matches!(
                output.value_type.as_str(),
                "boolean"
                    | "controlled-category"
                    | "bounded-identifier"
                    | "bounded-integer"
                    | "reviewed-structured-value"
                    | "boolean-list"
                    | "controlled-category-list"
                    | "bounded-identifier-list"
                    | "bounded-integer-list"
                    | "reviewed-structured-value-list"
            ) {
                push(
                    at.clone()
                        .key("outputs")
                        .map_key(name.to_string())
                        .key("type"),
                    "output-type",
                    "declare a bounded Evidence output type",
                );
            }
        }
    }
    for (id, source) in &project.sources {
        let at = FieldPath::root().key("sources").map_key(id.to_string());
        let allowed_request_keys: &[&str] = match source.source_type {
            SourceType::HttpJson => &["method", "path", "pathBindings", "fixedHeaders"],
            SourceType::SqliteExtract => &[
                "statement",
                "columns",
                "parameterBindings",
                "maximumRows",
                "maximumCellBytes",
                "maximumStatementSteps",
            ],
        };
        if let Some(request) = source.request.as_object() {
            for key in request
                .keys()
                .filter(|key| !allowed_request_keys.contains(&key.as_str()))
            {
                push(at.clone().key("request").map_key(key.clone()), "source-request-key", "declare request fields owned by this transport; selectors, response and resource bounds belong to their named Source fields");
            }
        } else {
            push(
                at.clone().key("request"),
                "source-request",
                "Source request must be a transport request mapping",
            );
        }
        if source.source_type == SourceType::SqliteExtract
            && source.prepare.is_none()
            && (source.adapter_parameters.is_some()
                || source.adapter_parameters_schema.is_some()
                || source.preparation_limits.is_some())
        {
            push(at.clone().key("prepare"), "source-preparation", "SQLite adapter parameters and preparation limits require a named preparation Function");
        }
        if let Some(batch) = &source.batch {
            if source.source_type != SourceType::HttpJson
                || !project
                    .acquisition_capabilities
                    .contains(&AcquisitionCapability::SourceBatch)
            {
                push(at.clone().key("batch"), "source-batch-capability", "source batching requires an HTTP Source and the source-batch package capability");
            }
            for (field, call, interface) in [
                ("prepare", &batch.prepare, FunctionInterface::SourcePrepare),
                ("extract", &batch.extract, FunctionInterface::SourceExtract),
            ] {
                if functions
                    .get(&call.function)
                    .is_none_or(|function| function.interface != interface)
                {
                    push(
                        at.clone().key("batch").key(field).key("function"),
                        "function-interface",
                        "batch call must name a Function with the matching source interface",
                    );
                }
            }
        }
        if functions
            .get(&source.extract.function)
            .is_none_or(|f| f.interface != FunctionInterface::SourceExtract)
        {
            push(
                at.clone().key("extract").key("function"),
                "function-interface",
                "extract must name a source-extract/v1 Function",
            );
        }
        if source.prepare.as_ref().is_some_and(|call| {
            functions
                .get(&call.function)
                .is_none_or(|f| f.interface != FunctionInterface::SourcePrepare)
        }) {
            push(
                at.clone().key("prepare").key("function"),
                "function-interface",
                "prepare must name a source-prepare/v1 Function",
            );
        }
        if source.source_type == SourceType::HttpJson && source.connection.is_none() {
            push(
                at.clone().key("connection"),
                "source-connection",
                "an HTTP Source must name a target-bound connection",
            );
        }
        if source.source_type == SourceType::SqliteExtract
            && (source.extract_profile.is_none() || source.maximum_extract_age_seconds.is_none())
        {
            push(
                at.clone(),
                "source-extract-binding",
                "a SQLite Source must name an extract profile and maximum age",
            );
        }
        for (index, selector) in source.selectors.iter().enumerate() {
            if selector.profiles.is_empty() {
                push(
                    at.clone().key("selectors").index(index).key("profiles"),
                    "source-selector",
                    "Source selectors must name existing profiles",
                );
            }
            for (profile_index, profile) in selector.profiles.iter().enumerate() {
                if !project.selector_profiles.contains_key(profile) {
                    push(
                        at.clone()
                            .key("selectors")
                            .index(index)
                            .key("profiles")
                            .index(profile_index),
                        "source-selector",
                        "name an existing selector profile",
                    );
                }
            }
        }
        if source.facts.is_empty() {
            push(
                at.clone().key("facts"),
                "source-facts",
                "declare the private fact schema",
            );
        }
    }
    findings
}

pub fn valid_asset(path: &str, extension: &str) -> bool {
    !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path.ends_with(&format!(".{extension}"))
}
fn absolute_uri(uri: &str) -> bool {
    url::Url::parse(uri).is_ok()
}

/// JSON Schema normalization for the bounded field vocabulary shared by facts
/// and response properties. This does not perform I/O or inspect source values.
pub fn value_schema(value: &Value) -> Value {
    let mut result = value.clone();
    if let Some(map) = result.as_object_mut() {
        let temporal_format = map
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| matches!(*kind, "date" | "date-time"))
            .map(str::to_owned);
        if let Some(value) = map.remove("minimumBytes") {
            map.insert("minLength".to_owned(), value);
        }
        if let Some(value) = map.remove("maximumBytes") {
            map.insert("maxLength".to_owned(), value);
        }
        if let Some(value) = map.remove("values") {
            map.insert("enum".to_owned(), value);
        }
        if let Some(Value::String(kind)) = map.get_mut("type") {
            match kind.as_str() {
                "controlled-category" | "bounded-identifier" | "date" | "date-time" => {
                    *kind = "string".to_owned()
                }
                "bounded-integer" => *kind = "integer".to_owned(),
                _ => {}
            }
        }
        if let Some(format) = temporal_format {
            map.insert("format".to_owned(), Value::String(format));
        }
        if map.get("type").and_then(Value::as_str) == Some("object") {
            map.entry("additionalProperties").or_insert(json!(false));
        }
        if let Some(Value::Object(properties)) = map.get_mut("properties") {
            for property in properties.values_mut() {
                *property = value_schema(property);
            }
        }
        if let Some(items) = map.get_mut("items") {
            *items = value_schema(items);
        }
    }
    result
}

/// Generated project result types use the same closed output declaration.
pub fn typescript(project: &EvidenceProject) -> String {
    let mut result = String::from(
        "// Generated from the normalized EvidenceProject.\nexport interface AssertionOutputs {\n",
    );
    for (id, definition) in &project.assertion_definitions {
        result.push_str(&format!(
            "  // evidence-definition: {id}\n  {}: {{\n",
            json!(id.as_str())
        ));
        for (name, output) in &definition.outputs {
            let scalar = match output.value_type.as_str().trim_end_matches("-list") {
                "boolean" => "boolean".to_owned(),
                "bounded-integer" => "number".to_owned(),
                "controlled-category" => output
                    .values
                    .iter()
                    .map(|v| json!(v).to_string())
                    .collect::<Vec<_>>()
                    .join(" | "),
                "bounded-identifier" => "string".to_owned(),
                _ => "unknown".to_owned(),
            };
            let shape = if output.value_type.ends_with("-list") {
                format!("ReadonlyArray<{scalar}>")
            } else {
                scalar
            };
            result.push_str(&format!("    {}: {};\n", json!(name.as_str()), shape));
        }
        result.push_str("  };\n");
    }
    result.push_str("}\nexport const assertionDefinitions = ");
    result.push_str(
        &serde_json::to_string_pretty(
            &project
                .assertion_definitions
                .iter()
                .map(|(id, d)| (id.as_str(), &d.semantics.requirement))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("string map is JSON"),
    );
    result.push_str(" as const;\n");
    result.push_str(&typescript_function_types(project));
    result
}

/// Python declarations keep local programmatic names while requests use URIs.
pub fn python(project: &EvidenceProject) -> String {
    let mut result = String::from("# Generated from the normalized EvidenceProject.\nfrom typing import Any, Literal, TypedDict\n\n");
    let mut definitions = Vec::new();
    for (id, definition) in &project.assertion_definitions {
        let class = id
            .as_str()
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_uppercase().chain(chars).collect()
                })
            })
            .collect::<String>();
        result.push_str(&format!(
            "# evidence-definition: {id}\n{class}Outputs = TypedDict({:?}, {{\n",
            format!("{class}Outputs")
        ));
        for (name, output) in &definition.outputs {
            let scalar = match output.value_type.as_str().trim_end_matches("-list") {
                "boolean" => "bool".to_owned(),
                "bounded-integer" => "int".to_owned(),
                "controlled-category" => format!(
                    "Literal[{}]",
                    output
                        .values
                        .iter()
                        .map(|value| json!(value).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "bounded-identifier" => "str".to_owned(),
                _ => "Any".to_owned(),
            };
            let shape = if output.value_type.ends_with("-list") {
                format!("list[{scalar}]")
            } else {
                scalar
            };
            result.push_str(&format!("    {}: {shape},\n", json!(name.as_str())));
        }
        result.push_str("})\n\n");
        definitions.push(format!(
            "    {}: {},",
            json!(id.as_str()),
            json!(definition.semantics.requirement)
        ));
    }
    result.push_str("ASSERTION_DEFINITIONS: dict[str, str] = {\n");
    result.push_str(&definitions.join("\n"));
    result.push_str("\n}\n");
    result.push_str(&python_source_types(project));
    result
}

fn schema_typescript(value: &Value) -> String {
    let value = value_schema(value);
    if let Some(values) = value.get("enum").and_then(Value::as_array) {
        return values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    match value.get("type").and_then(Value::as_str) {
        Some("boolean") => "boolean".to_owned(),
        Some("integer" | "number") => "number".to_owned(),
        Some("string") => "string".to_owned(),
        Some("null") => "null".to_owned(),
        Some("array") => format!("ReadonlyArray<{}>", schema_typescript(&value["items"])),
        Some("object") => {
            let required = value.get("required").and_then(Value::as_array);
            let fields = value
                .get("properties")
                .and_then(Value::as_object)
                .map(|properties| {
                    properties
                        .iter()
                        .map(|(name, shape)| {
                            format!(
                                "{}{}: {}",
                                json!(name),
                                if required.is_some_and(|required| required.contains(&json!(name)))
                                {
                                    ""
                                } else {
                                    "?"
                                },
                                schema_typescript(shape)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            format!("{{ {fields} }}")
        }
        _ => "unknown".to_owned(),
    }
}
fn source_facts_schema(source: &Source) -> Value {
    json!({"type":"object","required":source.facts.keys().collect::<Vec<_>>(),"properties":source.facts})
}
fn typescript_function_types(project: &EvidenceProject) -> String {
    let mut result = String::new();
    for (catalog, response) in [("SourceFacts", false), ("SourceResponses", true)] {
        result.push_str(&format!("export interface {catalog} {{\n"));
        for (id, source) in &project.sources {
            let shape = if response {
                source.response.shape.clone()
            } else {
                source_facts_schema(source)
            };
            result.push_str(&format!(
                "  // evidence-source: {id}\n  {}: {};\n",
                json!(id.as_str()),
                schema_typescript(&shape)
            ));
        }
        result.push_str("}\n");
    }
    result.push_str("export interface FunctionBindings {\n");
    for function in &project.functions {
        let mut calls = Vec::new();
        for (id, source) in &project.sources {
            let context = format!(
                "{{ parameters: {} }}",
                schema_typescript(
                    &source
                        .adapter_parameters_schema
                        .clone()
                        .unwrap_or_else(|| json!({"type":"object","properties":{}}))
                )
            );
            if source.extract.function == function.id {
                calls.push(format!("{{ source: {}; inputs: {{ response: SourceResponses[{}]; context: {} }}; outputs: {{ outcome: \"match\"; facts: SourceFacts[{}] }} | {{ outcome: \"no_match\" | \"ambiguous\" }} }}",json!(id.as_str()),json!(id.as_str()),context,json!(id.as_str())));
            }
            if source
                .prepare
                .as_ref()
                .is_some_and(|call| call.function == function.id)
            {
                calls.push(format!("{{ source: {}; inputs: {{ context: {} }}; outputs: {{ query: ReadonlyArray<{{ name: string; value: string }}>; body: unknown }} }}",json!(id.as_str()),context));
            }
        }
        for (id, definition) in &project.assertion_definitions {
            if definition.derive.function == function.id {
                let facts = definition
                    .acquisition
                    .source_ids()
                    .into_iter()
                    .map(|id| format!("SourceFacts[{}]", json!(id.as_str())))
                    .collect::<Vec<_>>()
                    .join(" & ");
                calls.push(format!("{{ definition: {}; inputs: {{ facts: {}; parameters: {} }}; outputs: AssertionOutputs[{}] }}",json!(id.as_str()),facts,schema_typescript(&json!({"type":"object","properties":definition.derive.parameters.iter().map(|(name,value)|(name.clone(),json!({"enum":[value]}))).collect::<serde_json::Map<_,_>>(),"required":definition.derive.parameters.keys().collect::<Vec<_>>()})),json!(id.as_str())));
            }
        }
        result.push_str(&format!(
            "  // evidence-function: {}\n  {}: {{ interface: {}; calls: {} }};\n",
            function.id,
            json!(function.id.as_str()),
            serde_json::to_string(&function.interface).expect("interface"),
            if calls.is_empty() {
                "never".to_owned()
            } else {
                calls.join(" | ")
            }
        ));
    }
    result.push_str("}\n");
    result
}
fn python_source_types(project: &EvidenceProject) -> String {
    let mut result = String::new();
    for (index, (id, source)) in project.sources.iter().enumerate() {
        result.push_str(&format!(
            "# evidence-source: {id}\nSource{index}Facts = TypedDict(\"Source{index}Facts\", {{\n"
        ));
        for (name, shape) in &source.facts {
            result.push_str(&format!(
                "    {}: {},\n",
                json!(name.as_str()),
                schema_python(shape)
            ));
        }
        result.push_str("})\n");
    }
    result.push_str("FUNCTION_INTERFACES: dict[str, str] = {\n");
    for function in &project.functions {
        result.push_str(&format!(
            "    # evidence-function: {}\n    {}: {},\n",
            function.id,
            json!(function.id.as_str()),
            serde_json::to_string(&function.interface).expect("interface")
        ));
    }
    result.push_str("}\n");
    result
}
fn schema_python(value: &Value) -> String {
    let value = value_schema(value);
    if let Some(values) = value.get("enum").and_then(Value::as_array) {
        return format!(
            "Literal[{}]",
            values
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    match value.get("type").and_then(Value::as_str) {
        Some("boolean") => "bool".to_owned(),
        Some("integer") => "int".to_owned(),
        Some("number") => "float".to_owned(),
        Some("string") => "str".to_owned(),
        Some("array") => format!("list[{}]", schema_python(&value["items"])),
        Some("object") => "dict[str, Any]".to_owned(),
        _ => "Any".to_owned(),
    }
}
