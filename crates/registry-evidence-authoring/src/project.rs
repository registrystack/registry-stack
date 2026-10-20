//! One normalized Evidence project. This module only transforms supplied values.
use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{
    duplicate_display_text_diagnostics, local_id_collision_diagnostics, ApiVersion,
    AuthoredDisplayText, AuthoredId, BoundedU64, Decoded, Diagnostic, EnvelopeRule, FormatSpec,
    LocalId, Report, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    finding::{FieldPath, Finding},
    formats::{decode_authored, findings_report},
};

pub const MAX_VALIDITY_SECONDS: u64 = 31_536_000;
pub const MAX_OUTPUTS_PER_ASSERTION: usize = 16;

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
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum FetchNoMatchPolicy {
    #[default]
    DependencyFailure,
    Unavailable,
}

impl FetchNoMatchPolicy {
    fn is_default(&self) -> bool {
        *self == Self::DependencyFailure
    }
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
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub description: Option<String>,
    pub maximum_aggregate_bytes: BoundedU64<1, 8192>,
    pub fields: BTreeMap<LocalId, crate::selector::Field>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Function {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
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
#[serde(deny_unknown_fields)]
pub struct DeriveSelectorInput {
    pub role: LocalId,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 8)))]
    pub alternatives: Vec<SelectorAlternative>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SelectorAlternative {
    pub profile: LocalId,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub fields: UniqueList<LocalId>,
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
    pub selector_inputs: Vec<DeriveSelectorInput>,
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
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub description: Option<String>,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::DisplayText")
    )]
    pub question: String,
    pub semantics: Semantics,
    pub purpose: String,
    pub grant_ceiling: GrantCeiling,
    pub subjects: Vec<Subject>,
    pub acquisition: Acquisition,
    pub derive: FunctionCall,
    #[cfg_attr(
        feature = "schema",
        schemars(extend(
            "minProperties" = 1,
            "maxProperties" = MAX_OUTPUTS_PER_ASSERTION
        ))
    )]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}
impl AuthorityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Statutory => "statutory",
            Self::Organizational => "organizational",
            Self::Consent => "consent",
            Self::Delegated => "delegated",
            Self::ExplicitRequest => "explicit-request",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    Human,
    Agent,
    Service,
}
impl ActorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ValueOrigin {
    Request,
    AuthenticatedContext,
    AuthenticatedGrant,
}
impl ValueOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::AuthenticatedContext => "authenticated-context",
            Self::AuthenticatedGrant => "authenticated-grant",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantCeiling {
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub authorities: UniqueList<AuthorityKind>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub actor_kinds: UniqueList<ActorKind>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub value_origins: UniqueList<ValueOrigin>,
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
        #[serde(
            default,
            rename = "onFetchNoMatch",
            skip_serializing_if = "FetchNoMatchPolicy::is_default"
        )]
        on_fetch_no_match: FetchNoMatchPolicy,
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
    /// Sources whose facts reach assertion derivation in the retained kernel.
    /// Search-then-fetch retains its search facts only for preparing the fetch.
    pub fn derivation_source_ids(&self) -> Vec<&LocalId> {
        match self {
            Self::SearchThenFetch { fetch, .. } => vec![fetch],
            _ => self.source_ids(),
        }
    }

    pub fn source_ids(&self) -> Vec<&LocalId> {
        match self {
            Self::Single { source } => vec![source],
            Self::SearchThenFetch { search, fetch, .. } => vec![search, fetch],
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
pub struct OutputProjection {
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 64),
            regex(pattern = "^[A-Za-z][A-Za-z0-9_]{0,63}$")
        )
    )]
    pub claim: String,
    pub disclosure: ProjectionDisclosure,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionDisclosure {
    TopLevel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Output {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub description: Option<String>,
    pub concept: String,
    #[serde(rename = "type")]
    #[cfg_attr(feature = "schema", schemars(extend("enum" = ["boolean","controlled-code","controlled-category","bounded-identifier","bounded-integer","bounded-decimal","date-bucket","time-bucket","audience-scoped-entity-reference","controlled-code-list","entity-reference-list","reviewed-structured-value"])))]
    pub value_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<crate::output::Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<crate::output::Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_bytes: Option<BoundedU64<1, 1024>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_bytes: Option<BoundedU64<1, 8192>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_items: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_items: Option<BoundedU64<1, 64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_serialized_bytes: Option<BoundedU64<1, 65536>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<OutputProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codelist: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codelist_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_scale: Option<BoundedU64<0, 9>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    /// Optional presentation label. Stable references use the identifier.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
    pub label: Option<String>,
    /// Human explanation for authors and reviewers; excluded from behavior revisions.
    #[serde(
        default,
        deserialize_with = "registry_platform_yaml::optional_display_text",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::DisplayText>")
    )]
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
    let mut decoded = decode_authored::<EvidenceProject>(file, bytes, &PROJECT)?;
    let mut report = findings_report(
        &decoded.document,
        "project",
        validate_project(&decoded.value),
    );
    report.extend(Report::new(project_integrity_diagnostics(&mut decoded)));
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

fn project_integrity_diagnostics(decoded: &mut Decoded<EvidenceProject>) -> Vec<Diagnostic> {
    fn collisions(
        document: &registry_platform_yaml::Document,
        code: &str,
        values: &[(String, String)],
    ) -> Vec<Diagnostic> {
        let entries = values
            .iter()
            .map(|(id, pointer)| AuthoredId { id, pointer })
            .collect::<Vec<_>>();
        local_id_collision_diagnostics(document, code, &entries)
    }
    fn warnings(
        document: &registry_platform_yaml::Document,
        code: &str,
        kind: &str,
        values: &[(String, String, String)],
    ) -> Vec<Diagnostic> {
        let entries = values
            .iter()
            .map(|(id, text, pointer)| AuthoredDisplayText { id, text, pointer })
            .collect::<Vec<_>>();
        duplicate_display_text_diagnostics(document, code, kind, &entries)
    }
    fn map_ids<T>(base: &str, values: &BTreeMap<LocalId, T>) -> Vec<(String, String)> {
        values
            .keys()
            .map(|id| {
                let id = id.as_str().to_owned();
                let pointer = format!(
                    "{base}/{}",
                    registry_platform_yaml::escape_pointer_segment(&id)
                );
                (id, pointer)
            })
            .collect()
    }

    let project = &decoded.value;
    let document = &decoded.document;
    let mut errors = Vec::new();
    for (code, values) in [
        (
            "evidence.project.selector-profile-id-collision",
            map_ids("/selectorProfiles", &project.selector_profiles),
        ),
        (
            "evidence.project.function-id-collision",
            project
                .functions
                .iter()
                .enumerate()
                .map(|(index, function)| {
                    (
                        function.id.as_str().to_owned(),
                        format!("/functions/{index}/id"),
                    )
                })
                .collect(),
        ),
        (
            "evidence.project.source-id-collision",
            map_ids("/sources", &project.sources),
        ),
        (
            "evidence.project.assertion-definition-id-collision",
            map_ids("/assertionDefinitions", &project.assertion_definitions),
        ),
    ] {
        errors.extend(collisions(document, code, &values));
    }
    for (profile_id, profile) in &project.selector_profiles {
        errors.extend(collisions(
            document,
            "evidence.project.selector-field-id-collision",
            &map_ids(
                &format!(
                    "/selectorProfiles/{}/fields",
                    registry_platform_yaml::escape_pointer_segment(profile_id.as_str())
                ),
                &profile.fields,
            ),
        ));
    }
    for (source_id, source) in &project.sources {
        errors.extend(collisions(
            document,
            "evidence.project.source-fact-id-collision",
            &map_ids(
                &format!(
                    "/sources/{}/facts",
                    registry_platform_yaml::escape_pointer_segment(source_id.as_str())
                ),
                &source.facts,
            ),
        ));
        let roles = source
            .selectors
            .iter()
            .enumerate()
            .map(|(index, selector)| {
                (
                    selector.role.as_str().to_owned(),
                    format!(
                        "/sources/{}/selectors/{index}/role",
                        registry_platform_yaml::escape_pointer_segment(source_id.as_str())
                    ),
                )
            })
            .collect::<Vec<_>>();
        errors.extend(collisions(
            document,
            "evidence.project.source-selector-role-collision",
            &roles,
        ));
    }
    for (assertion_id, assertion) in &project.assertion_definitions {
        let base = format!(
            "/assertionDefinitions/{}",
            registry_platform_yaml::escape_pointer_segment(assertion_id.as_str())
        );
        errors.extend(collisions(
            document,
            "evidence.project.output-id-collision",
            &map_ids(&format!("{base}/outputs"), &assertion.outputs),
        ));
        let roles = assertion
            .subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| {
                (
                    subject.role.as_str().to_owned(),
                    format!("{base}/subjects/{index}/role"),
                )
            })
            .collect::<Vec<_>>();
        errors.extend(collisions(
            document,
            "evidence.project.subject-role-collision",
            &roles,
        ));
    }

    let mut found_warnings = Vec::new();
    let top_groups = [
        (
            "evidence.project.duplicate-selector-profile-label",
            "selector profiles",
            project
                .selector_profiles
                .iter()
                .filter_map(|(id, item)| {
                    item.label.as_ref().map(|label| {
                        let pointer = format!(
                            "/selectorProfiles/{}/label",
                            registry_platform_yaml::escape_pointer_segment(id.as_str())
                        );
                        (id.as_str().to_owned(), label.clone(), pointer)
                    })
                })
                .collect::<Vec<_>>(),
        ),
        (
            "evidence.project.duplicate-function-label",
            "functions",
            project
                .functions
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    item.label.as_ref().map(|label| {
                        (
                            item.id.as_str().to_owned(),
                            label.clone(),
                            format!("/functions/{index}/label"),
                        )
                    })
                })
                .collect(),
        ),
        (
            "evidence.project.duplicate-source-label",
            "sources",
            project
                .sources
                .iter()
                .filter_map(|(id, item)| {
                    item.label.as_ref().map(|label| {
                        let pointer = format!(
                            "/sources/{}/label",
                            registry_platform_yaml::escape_pointer_segment(id.as_str())
                        );
                        (id.as_str().to_owned(), label.clone(), pointer)
                    })
                })
                .collect(),
        ),
        (
            "evidence.project.duplicate-assertion-label",
            "assertion definitions",
            project
                .assertion_definitions
                .iter()
                .map(|(id, item)| {
                    let (text, member) = item
                        .label
                        .as_ref()
                        .map_or((&item.question, "question"), |label| (label, "label"));
                    let pointer = format!(
                        "/assertionDefinitions/{}/{member}",
                        registry_platform_yaml::escape_pointer_segment(id.as_str())
                    );
                    (id.as_str().to_owned(), text.clone(), pointer)
                })
                .collect(),
        ),
    ];
    for (code, kind, values) in &top_groups {
        found_warnings.extend(warnings(document, code, kind, values));
    }
    for (profile_id, profile) in &project.selector_profiles {
        let values = profile
            .fields
            .iter()
            .filter_map(|(id, field)| {
                field.label().map(|label| {
                    let pointer = format!(
                        "/selectorProfiles/{}/fields/{}/label",
                        registry_platform_yaml::escape_pointer_segment(profile_id.as_str()),
                        registry_platform_yaml::escape_pointer_segment(id.as_str())
                    );
                    (id.as_str().to_owned(), label.to_owned(), pointer)
                })
            })
            .collect::<Vec<_>>();
        found_warnings.extend(warnings(
            document,
            "evidence.project.duplicate-selector-field-label",
            "selector fields",
            &values,
        ));
    }
    for (assertion_id, assertion) in &project.assertion_definitions {
        let values = assertion
            .outputs
            .iter()
            .filter_map(|(id, output)| {
                output.label.as_ref().map(|label| {
                    let pointer = format!(
                        "/assertionDefinitions/{}/outputs/{}/label",
                        registry_platform_yaml::escape_pointer_segment(assertion_id.as_str()),
                        registry_platform_yaml::escape_pointer_segment(id.as_str())
                    );
                    (id.as_str().to_owned(), label.clone(), pointer)
                })
            })
            .collect::<Vec<_>>();
        found_warnings.extend(warnings(
            document,
            "evidence.project.duplicate-output-label",
            "assertion outputs",
            &values,
        ));
    }
    for warning in found_warnings {
        decoded.document.push_warning(warning);
    }
    errors
}

pub fn validate_project(project: &EvidenceProject) -> Vec<Finding> {
    let mut findings = project
        .selector_profiles
        .iter()
        .flat_map(|(id, profile)| {
            crate::selector::validate(
                profile,
                &FieldPath::root()
                    .key("selectorProfiles")
                    .map_key(id.to_string()),
            )
        })
        .collect::<Vec<_>>();
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
        let purpose = definition.purpose.as_bytes();
        if purpose.is_empty()
            || purpose.len() > 128
            || !purpose[0].is_ascii_lowercase()
            || !purpose.iter().skip(1).all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(byte)
            })
        {
            push(
                at.clone().key("purpose"),
                "definition-purpose",
                "declare a bounded lowercase purpose code",
            );
        }
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
        if definition.grant_ceiling.authorities.len() > 5
            || definition.grant_ceiling.actor_kinds.len() > 3
            || definition.grant_ceiling.value_origins.len() > 3
            || definition.grant_ceiling.audiences.len() > 32
        {
            push(at.clone().key("grantCeiling"),"grant-ceiling-bounds","keep each complete ceiling within the retained authority, actor, value-origin and audience bounds");
        }
        for (index, audience) in definition.grant_ceiling.audiences.iter().enumerate() {
            if audience.is_empty()
                || audience.len() > 2048
                || audience
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
                || !absolute_uri(audience)
            {
                push(
                    at.clone().key("grantCeiling").key("audiences").index(index),
                    "grant-ceiling-audience",
                    "declare a bounded absolute audience URI without whitespace",
                );
            }
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
            Acquisition::SearchThenFetch { search, fetch, .. } => vec![
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
        if definition.outputs.is_empty() || definition.outputs.len() > MAX_OUTPUTS_PER_ASSERTION {
            push(
                at.clone().key("outputs"),
                "output-count",
                "declare between one and 16 public Outputs",
            );
        }
        let mut selector_roles = BTreeSet::new();
        if definition.derive.selector_inputs.len() > 8 {
            push(
                at.clone().key("derive").key("selectorInputs"),
                "derive-selectors",
                "declare at most eight typed selector inputs",
            );
        }
        for (index, input) in definition.derive.selector_inputs.iter().enumerate() {
            let input_at = at.clone().key("derive").key("selectorInputs").index(index);
            if !selector_roles.insert(&input.role)
                || !definition
                    .subjects
                    .iter()
                    .any(|subject| subject.role == input.role)
                || input.alternatives.is_empty()
                || input.alternatives.len() > 8
            {
                push(
                    input_at.clone(),
                    "derive-selectors",
                    "declare distinct subject roles with one to eight allowed profile alternatives",
                );
            }
            let mut alternatives = BTreeSet::new();
            for (alt_index, alternative) in input.alternatives.iter().enumerate() {
                if !alternatives.insert(&alternative.profile)
                    || alternative.fields.is_empty()
                    || alternative.fields.len() > 16
                    || !definition.subjects.iter().any(|subject| {
                        subject.role == input.role
                            && subject.selectors.contains(&alternative.profile)
                    })
                    || project
                        .selector_profiles
                        .get(&alternative.profile)
                        .is_none_or(|profile| {
                            alternative
                                .fields
                                .iter()
                                .any(|name| !profile.fields.contains_key(name))
                        })
                {
                    push(
                        input_at.clone().key("alternatives").index(alt_index),
                        "derive-selector-profile",
                        "name an allowed profile and one to 16 distinct declared fields",
                    );
                }
            }
        }
        let mut projected_claims = BTreeSet::new();
        for (name, output) in &definition.outputs {
            if let Some(projection) = &output.sd_jwt_vc {
                if output.value_type != "reviewed-structured-value" {
                    push(
                        at.clone()
                            .key("outputs")
                            .map_key(name.to_string())
                            .key("sdJwtVc"),
                        "output-projection-type",
                        "SD-JWT VC field projection requires a reviewed structured value",
                    );
                }
                if !crate::validate::validate_sd_jwt_claim_name(&projection.claim).is_empty()
                    || !projected_claims.insert(&projection.claim)
                {
                    push(
                        at.clone()
                            .key("outputs")
                            .map_key(name.to_string())
                            .key("sdJwtVc")
                            .key("claim"),
                        "output-projection-claim",
                        "declare a distinct bounded SD-JWT VC claim name",
                    );
                }
            }

            if !crate::output::valid(output) {
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
            if !crate::output::TYPES.contains(&output.value_type.as_str()) {
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
    findings.extend(crate::acquisition_validation::validate(project));
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
    uri.len() <= 2048
        && !uri
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        && url::Url::parse(uri).is_ok()
}

/// JSON Schema normalization for the bounded field vocabulary shared by facts
/// and response properties. This does not perform I/O or inspect source values.
pub fn value_schema(value: &Value) -> Value {
    let mut result = value.clone();
    if let Some(map) = result.as_object_mut() {
        let temporal_format = map
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| matches!(*kind, "date" | "date-time" | "uuid"))
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
                "controlled-category" | "bounded-identifier" | "date" | "date-time" | "uuid" => {
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
pub use crate::types::{python, typescript};
