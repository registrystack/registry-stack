// SPDX-License-Identifier: Apache-2.0
//! Strict governed and deployment input contracts.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::ops::Deref;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;

const OIDC_DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

pub(crate) const MAXIMUM_ACCESS_PROFILE_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAXIMUM_RUNTIME_BYTES: u64 = 1024 * 1024;

// A JSON string byte can expand to six bytes (`\u00XX`). Capping the authored
// audience at 8 KiB therefore leaves more than 16,000 bytes in the 64 KiB
// decoded JWT claims segment for object syntax and registered claims. Its
// base64url form also remains well inside the 128 KiB complete-token ceiling,
// with ample room for the protected header, signature, and separators.
const MAXIMUM_ISSUER_AUDIENCE_BYTES: usize = 8 * 1024;

/// A duplicate-free insertion-ordered YAML mapping.
///
/// Property and selector order is authored behavior, while ordinary map
/// containers would erase both duplicate keys and order before compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedMap<T>(Vec<(String, T)>);

impl<T> Default for OrderedMap<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> OrderedMap<T> {
    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.0.iter().map(|(key, value)| (key.as_str(), value))
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.0
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(key, _)| key.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<T> Deref for OrderedMap<T> {
    type Target = [(String, T)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Serialize for OrderedMap<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[cfg(feature = "schema")]
impl<T: schemars::JsonSchema> schemars::JsonSchema for OrderedMap<T> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(format!("OrderedMap_of_{}", T::schema_name()))
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(format!("OrderedMap<{}>", T::schema_id()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <std::collections::BTreeMap<String, T>>::json_schema(generator)
    }
}

struct OrderedMapVisitor<T>(std::marker::PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for OrderedMapVisitor<T> {
    type Value = OrderedMap<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a mapping with unique string keys")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = Vec::with_capacity(access.size_hint().unwrap_or(0));
        let mut names = HashSet::with_capacity(access.size_hint().unwrap_or(0));
        while let Some((key, value)) = access.next_entry::<String, T>()? {
            if !names.insert(key.clone()) {
                return Err(de::Error::custom(format_args!(
                    "duplicate mapping key `{key}`"
                )));
            }
            entries.push((key, value));
        }
        Ok(OrderedMap(entries))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OrderedMap<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(OrderedMapVisitor(std::marker::PhantomData))
    }
}

#[derive(Debug, Error)]
#[error("contract YAML is not valid")]
pub struct ContractParseError {
    #[source]
    source: serde_norway::Error,
}

impl ContractParseError {
    pub fn detail(&self) -> &serde_norway::Error {
        &self.source
    }
}

/// Governed Relay-owned Registry input. Unknown fields are rejected at every
/// nested structure rather than silently becoming deployment behavior.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryContract {
    pub api_version: String,
    pub kind: String,
    pub metadata: ContractMetadata,
    pub registry: RegistryDefinition,
    pub governance: Governance,
    #[serde(default)]
    pub publication: Option<Publication>,
    pub semantics: Semantics,
    pub classifications: ClassificationCatalog,
    pub sources: OrderedMap<SourceDefinition>,
    #[serde(default)]
    pub resources: Vec<ResourceDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statistical_datasets: Vec<StatisticalDatasetDefinition>,
    pub metadata_visibility: MetadataVisibility,
}

pub const MAXIMUM_PUBLICATION_JURISDICTIONS: usize =
    registry_discovery_profile::MAX_IDENTIFIER_VALUES;

/// Public facts the Registry author explicitly elects to publish for
/// discovery. All other description fields are derived from already governed
/// Registry identity, service, role, and operation contracts.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Publication {
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAXIMUM_PUBLICATION_JURISDICTIONS))
    )]
    pub jurisdictions: Vec<String>,
}

impl RegistryContract {
    pub fn parse_yaml(input: &str) -> Result<Self, ContractParseError> {
        serde_norway::from_str(input).map_err(|source| ContractParseError { source })
    }
}

pub(crate) fn runtime_cursor_configuration_is_valid(
    contract: &RegistryContract,
    runtime: &RelayRuntime,
) -> bool {
    runtime.cursor.is_some()
        || (!contract.resources.iter().any(|resource| {
            resource.operations.list.is_some() || !resource.operations.searches.is_empty()
        }) && contract
            .resources
            .iter()
            .filter(|resource| {
                resource_can_appear_in_metadata(resource, contract.metadata_visibility.resources)
            })
            .take(2)
            .count()
            <= 1)
}

pub(crate) fn contract_has_protected_access(contract: &RegistryContract) -> bool {
    contract
        .resources
        .iter()
        .flat_map(resource_access_rules)
        .chain(
            contract
                .statistical_datasets
                .iter()
                .map(|dataset| &dataset.access),
        )
        .any(|access| matches!(access, AccessRule::Protected(_)))
}

fn resource_can_appear_in_metadata(resource: &ResourceDefinition, visibility: Visibility) -> bool {
    if visibility == Visibility::OperatorOnly {
        return false;
    }
    resource_access_rules(resource).any(|access| {
        visibility == Visibility::OperationBound || matches!(access, AccessRule::Public(_))
    })
}

fn resource_access_rules(resource: &ResourceDefinition) -> impl Iterator<Item = &AccessRule> {
    resource
        .operations
        .list
        .iter()
        .flat_map(|operation| {
            operation
                .access_profiles
                .iter()
                .map(|(_, item)| &item.access)
        })
        .chain(resource.operations.read.iter().flat_map(|operation| {
            operation
                .access_profiles
                .iter()
                .map(|(_, item)| &item.access)
        }))
        .chain(resource.operations.lookups.iter().flat_map(|operation| {
            operation
                .access_profiles
                .iter()
                .map(|(_, item)| &item.access)
        }))
        .chain(resource.operations.searches.iter().flat_map(|operation| {
            operation
                .access_profiles
                .iter()
                .map(|(_, item)| &item.access)
        }))
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContractMetadata {
    pub id: String,
    pub version: String,
    pub title: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryDefinition {
    pub registry_identifier: String,
    pub name: String,
    pub authority: Institution,
    #[serde(default)]
    pub operator: Option<Institution>,
    pub authoritative_scope: String,
    pub base_uri: String,
    pub identifier_lifecycle_policy_ref: String,
    pub alignment_targets: Vec<AlignmentTarget>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Institution {
    pub identifier: String,
    pub name: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlignmentTarget {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub cfr_target: Option<String>,
    pub status: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Governance {
    pub controller: String,
    pub publisher: String,
    pub audit_owner: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Semantics {
    pub local_vocabulary: String,
    #[serde(default)]
    pub alignments: Vec<SemanticAlignment>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SemanticAlignment {
    pub id: String,
    pub version: String,
    pub profile_ref: String,
    pub digest: String,
    pub relation_required: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassificationCatalog {
    pub privacy: SchemeVersion,
    pub institutional: SchemeVersion,
    pub handling: SchemeVersion,
    pub provenance_ref: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchemeVersion {
    pub scheme: String,
    pub version: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceDefinition {
    pub kind: String,
    pub profile: SourceProfile,
    pub expected_schema_fingerprint: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceProfile {
    Snapshot,
    LiveReadOnly,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub id: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
    pub title: String,
    pub description: String,
    pub semantic_class: String,
    pub source: ResourceSource,
    pub classification_defaults: ClassificationPartial,
    pub record_context: RecordContext,
    #[serde(default)]
    pub source_column_classifications: OrderedMap<ClassificationPartial>,
    pub properties: OrderedMap<PropertyDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_geometry: Option<String>,
    pub disclosure_profiles: OrderedMap<DisclosureProfile>,
    pub operations: Operations,
    #[serde(default)]
    pub processing_descriptions: Vec<ProcessingDescription>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceSource {
    pub source: String,
    pub view: String,
}

/// One governed, pre-aggregated statistical dataset. The authored shape is
/// independent of the fixed SDMX exchange binding compiled from it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalDatasetDefinition {
    pub id: String,
    pub title: String,
    pub description: String,
    pub publication: StatisticalPublication,
    pub source: ResourceSource,
    pub classification_defaults: ClassificationPartial,
    #[serde(default)]
    pub source_column_classifications: OrderedMap<ClassificationPartial>,
    pub dimensions: OrderedMap<StatisticalDimensionDefinition>,
    pub time: StatisticalTimeDimensionDefinition,
    pub measure: StatisticalMeasureDefinition,
    #[serde(default)]
    pub attributes: OrderedMap<StatisticalAttributeDefinition>,
    pub access: AccessRule,
    pub query: StatisticalQueryProfile,
    pub bindings: StatisticalBindings,
    #[serde(default)]
    pub processing_descriptions: Vec<ProcessingDescription>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalPublication {
    pub release_at: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalDimensionDefinition {
    pub label: String,
    pub description: String,
    pub column: String,
    #[serde(rename = "type")]
    pub data_type: StatisticalValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    pub concept: String,
    #[serde(default)]
    pub classification: ClassificationPartial,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalTimeDimensionDefinition {
    pub label: String,
    pub description: String,
    pub column: String,
    pub granularity: StatisticalTimeGranularity,
    pub concept: String,
    #[serde(default)]
    pub classification: ClassificationPartial,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StatisticalTimeGranularity {
    Annual,
    Quarterly,
    Monthly,
    Daily,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalMeasureDefinition {
    pub id: String,
    pub label: String,
    pub description: String,
    pub column: String,
    #[serde(rename = "type")]
    pub data_type: StatisticalValueType,
    pub concept: String,
    #[serde(default)]
    pub classification: ClassificationPartial,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalAttributeDefinition {
    pub label: String,
    pub description: String,
    pub column: String,
    #[serde(rename = "type")]
    pub data_type: StatisticalValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    pub required: bool,
    pub concept: String,
    #[serde(default)]
    pub classification: ClassificationPartial,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StatisticalValueType {
    Code,
    String,
    Integer,
    Decimal,
    Boolean,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalQueryProfile {
    pub allow_unfiltered: bool,
    pub maximum_observations: u32,
    pub maximum_offset: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalBindings {
    pub sdmx: SdmxBindingDefinition,
}

/// Optional identity overrides for the fixed compiler-owned SDMX profile.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SdmxBindingDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agency_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_structure_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concept_scheme_id: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassificationPartial {
    #[serde(default)]
    pub privacy: Option<String>,
    #[serde(default)]
    pub institutional: Option<String>,
    #[serde(default)]
    pub handling: Option<Handling>,
    #[serde(default)]
    pub status: Option<ReviewStatus>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Handling {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewStatus {
    Reviewed,
    Suggested,
    Uncertain,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordContext {
    pub record_identifier: ColumnBinding,
    pub revision_identifier: ColumnBinding,
    pub lifecycle_state: CodelistColumnBinding,
    pub recorded_at: ColumnBinding,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ColumnBinding {
    pub source_column: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CodelistColumnBinding {
    pub source_column: String,
    pub codelist: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyDefinition {
    pub label: String,
    pub description: String,
    pub source_required: bool,
    pub semantic_term: String,
    pub classification: ClassificationPartial,
    pub binding: PropertyBindingDefinition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyBindingDefinition {
    Scalar(ScalarPropertyBinding),
    Point(PointPropertyBinding),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarPropertyBinding {
    pub source_column: String,
    pub data_type: DataType,
    pub codelist: Option<String>,
    pub transform: Option<TransformDefinition>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PointPropertyBinding {
    pub crs: String,
    pub source: PointSourceDefinition,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PointSourceDefinition {
    pub longitude_column: String,
    pub latitude_column: String,
}

impl PropertyDefinition {
    #[must_use]
    pub fn scalar_binding(&self) -> Option<&ScalarPropertyBinding> {
        match &self.binding {
            PropertyBindingDefinition::Scalar(binding) => Some(binding),
            PropertyBindingDefinition::Point(_) => None,
        }
    }

    #[must_use]
    pub fn point_binding(&self) -> Option<&PointPropertyBinding> {
        match &self.binding {
            PropertyBindingDefinition::Point(binding) => Some(binding),
            PropertyBindingDefinition::Scalar(_) => None,
        }
    }
}

impl Serialize for PropertyDefinition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("label", &self.label)?;
        map.serialize_entry("description", &self.description)?;
        match &self.binding {
            PropertyBindingDefinition::Scalar(binding) => {
                map.serialize_entry("sourceColumn", &binding.source_column)?;
                map.serialize_entry("type", &binding.data_type)?;
                map.serialize_entry("codelist", &binding.codelist)?;
                map.serialize_entry("sourceRequired", &self.source_required)?;
                map.serialize_entry("semanticTerm", &self.semantic_term)?;
                map.serialize_entry("transform", &binding.transform)?;
            }
            PropertyBindingDefinition::Point(binding) => {
                map.serialize_entry("type", "point")?;
                map.serialize_entry("crs", &binding.crs)?;
                map.serialize_entry("source", &binding.source)?;
                map.serialize_entry("sourceRequired", &self.source_required)?;
                map.serialize_entry("semanticTerm", &self.semantic_term)?;
            }
        }
        map.serialize_entry("classification", &self.classification)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for PropertyDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PropertyDefinitionVisitor)
    }
}

struct PropertyDefinitionVisitor;

impl<'de> Visitor<'de> for PropertyDefinitionVisitor {
    type Value = PropertyDefinition;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed scalar or point property definition")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut label = None;
        let mut description = None;
        let mut source_column = None;
        let mut property_type = None;
        let mut codelist = None;
        let mut source_required = None;
        let mut semantic_term = None;
        let mut transform = None;
        let mut classification = None;
        let mut crs = None;
        let mut source = None;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "label" => set_once(&mut label, map.next_value()?, "label")?,
                "description" => set_once(&mut description, map.next_value()?, "description")?,
                "sourceColumn" => set_once(&mut source_column, map.next_value()?, "sourceColumn")?,
                "type" => set_once(&mut property_type, map.next_value()?, "type")?,
                "codelist" => set_once(&mut codelist, map.next_value()?, "codelist")?,
                "sourceRequired" => {
                    set_once(&mut source_required, map.next_value()?, "sourceRequired")?
                }
                "semanticTerm" => set_once(&mut semantic_term, map.next_value()?, "semanticTerm")?,
                "transform" => set_once(&mut transform, map.next_value()?, "transform")?,
                "classification" => {
                    set_once(&mut classification, map.next_value()?, "classification")?
                }
                "crs" => set_once(&mut crs, map.next_value()?, "crs")?,
                "source" => set_once(&mut source, map.next_value()?, "source")?,
                _ => return Err(de::Error::unknown_field(&field, PROPERTY_FIELDS)),
            }
        }

        let label = label.ok_or_else(|| de::Error::missing_field("label"))?;
        let description = description.ok_or_else(|| de::Error::missing_field("description"))?;
        let property_type: String =
            property_type.ok_or_else(|| de::Error::missing_field("type"))?;
        let source_required =
            source_required.ok_or_else(|| de::Error::missing_field("sourceRequired"))?;
        let semantic_term =
            semantic_term.ok_or_else(|| de::Error::missing_field("semanticTerm"))?;
        let classification = classification.unwrap_or_default();

        let binding = if property_type == "point" {
            if source_column.is_some() || codelist.is_some() || transform.is_some() {
                return Err(de::Error::custom(
                    "point properties reject scalar sourceColumn, codelist, and transform fields",
                ));
            }
            PropertyBindingDefinition::Point(PointPropertyBinding {
                crs: crs.ok_or_else(|| de::Error::missing_field("crs"))?,
                source: source.ok_or_else(|| de::Error::missing_field("source"))?,
            })
        } else {
            if crs.is_some() || source.is_some() {
                return Err(de::Error::custom(
                    "scalar properties reject point crs and source fields",
                ));
            }
            let data_type = match property_type.as_str() {
                "string" => DataType::String,
                "boolean" => DataType::Boolean,
                "integer" => DataType::Integer,
                "date" => DataType::Date,
                "date-time" => DataType::DateTime,
                "year" => DataType::Year,
                "year-month" => DataType::YearMonth,
                "controlled-code" => DataType::ControlledCode,
                _ => return Err(de::Error::unknown_variant(&property_type, PROPERTY_TYPES)),
            };
            PropertyBindingDefinition::Scalar(ScalarPropertyBinding {
                source_column: source_column
                    .ok_or_else(|| de::Error::missing_field("sourceColumn"))?,
                data_type,
                codelist: codelist.unwrap_or_default(),
                transform: transform.unwrap_or_default(),
            })
        };

        Ok(PropertyDefinition {
            label,
            description,
            source_required,
            semantic_term,
            classification,
            binding,
        })
    }
}

fn set_once<T, E>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if slot.replace(value).is_some() {
        Err(E::duplicate_field(field))
    } else {
        Ok(())
    }
}

const PROPERTY_FIELDS: &[&str] = &[
    "label",
    "description",
    "sourceColumn",
    "type",
    "codelist",
    "sourceRequired",
    "semanticTerm",
    "transform",
    "classification",
    "crs",
    "source",
];

const PROPERTY_TYPES: &[&str] = &[
    "string",
    "boolean",
    "integer",
    "date",
    "date-time",
    "year",
    "year-month",
    "controlled-code",
    "point",
];

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PropertyDefinition {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("PropertyDefinition")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::PropertyDefinition"))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        PropertyDefinitionSchema::json_schema(generator)
    }
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(untagged)]
enum PropertyDefinitionSchema {
    Scalar(ScalarPropertyDefinitionSchema),
    Point(PointPropertyDefinitionSchema),
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ScalarPropertyDefinitionSchema {
    label: String,
    description: String,
    source_column: String,
    #[serde(rename = "type")]
    data_type: DataType,
    #[serde(default)]
    codelist: Option<String>,
    source_required: bool,
    semantic_term: String,
    #[serde(default)]
    transform: Option<TransformDefinition>,
    #[serde(default)]
    classification: ClassificationPartial,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PointPropertyDefinitionSchema {
    label: String,
    description: String,
    #[serde(rename = "type")]
    data_type: PointPropertyType,
    crs: String,
    source: PointSourceDefinition,
    source_required: bool,
    semantic_term: String,
    #[serde(default)]
    classification: ClassificationPartial,
}

#[cfg(feature = "schema")]
#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum PointPropertyType {
    Point,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DataType {
    String,
    Boolean,
    Integer,
    Date,
    DateTime,
    Year,
    YearMonth,
    ControlledCode,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TransformDefinition {
    PartialString {
        reveal: PartialStringReveal,
        characters: u16,
    },
    DatePrecision {
        #[serde(rename = "sourceType")]
        source_type: DateInputType,
        precision: DatePrecision,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PartialStringReveal {
    Prefix,
    Suffix,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DateInputType {
    Date,
    DateTime,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DatePrecision {
    Year,
    YearMonth,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DisclosureProfile {
    pub properties: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Operations {
    #[serde(default)]
    pub list: Option<ListOperation>,
    #[serde(default)]
    pub read: Option<RecordOperation>,
    #[serde(default)]
    pub lookups: Vec<LookupOperation>,
    #[serde(default)]
    pub searches: Vec<SearchOperation>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListOperation {
    pub default_access_profile: String,
    pub access_profiles: OrderedMap<AccessProfileDefinition>,
    #[serde(default)]
    pub filters: Vec<FilterDefinition>,
    pub allow_unfiltered: bool,
    pub order_by: Vec<String>,
    pub pagination: Pagination,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordOperation {
    pub default_access_profile: String,
    pub access_profiles: OrderedMap<AccessProfileDefinition>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupOperation {
    pub id: String,
    pub request_body: LookupRequestBody,
    pub default_access_profile: String,
    pub access_profiles: OrderedMap<AccessProfileDefinition>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SearchOperation {
    pub id: String,
    pub query: SearchQueryDefinition,
    pub default_access_profile: String,
    pub access_profiles: OrderedMap<AccessProfileDefinition>,
    pub order_by: Vec<String>,
    pub pagination: Pagination,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SearchQueryDefinition {
    PointBbox {
        maximum_longitude_span_degrees: u16,
        maximum_latitude_span_degrees: u16,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessProfileDefinition {
    pub access: AccessRule,
    pub disclosure_profile: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassificationReviewDocument {
    pub api_version: String,
    pub kind: String,
    pub registry_identifier: String,
    pub classification_inventory_digest: String,
    pub method: IdentificationMethod,
    pub reviewer: String,
    pub review_date: String,
    pub status: ReviewStatus,
    pub rationale_ref: String,
    #[serde(default)]
    pub generated_identification: Option<GeneratedIdentificationBinding>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationMethod {
    Generated,
    Imported,
    Manual,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratedIdentificationBinding {
    pub report_ref: String,
    pub report_digest: String,
    pub rule_pack: RulePackBinding,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RulePackBinding {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AccessRule {
    Public(String),
    Protected(ProtectedAccess),
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtectedAccess {
    pub scope: String,
    #[serde(default)]
    pub purpose: Option<PurposeConstraint>,
    #[serde(default)]
    pub authority_row_binding: Option<AuthorityRowBinding>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PurposeConstraint {
    pub claim: String,
    pub allowed: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AuthorityRowBinding {
    Claim(ClaimRowBinding),
    Principal(PrincipalRowBinding),
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClaimRowBinding {
    pub claim: String,
    pub source_column: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrincipalRowBinding {
    pub principal: bool,
    pub source_column: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FilterDefinition {
    pub name: String,
    pub property: String,
    #[serde(rename = "type")]
    pub data_type: DataType,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pagination {
    pub default_page_size: u32,
    pub maximum_page_size: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupRequestBody {
    pub maximum_bytes: u32,
    pub selectors: OrderedMap<SelectorDefinition>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectorDefinition {
    pub source_column: String,
    #[serde(rename = "type")]
    pub data_type: DataType,
    #[serde(default)]
    pub minimum_bytes: Option<u32>,
    #[serde(default)]
    pub maximum_bytes: Option<u32>,
    #[serde(default)]
    pub codelist: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProcessingDescription {
    pub id: String,
    pub operation_refs: Vec<String>,
    pub purpose: String,
    pub recipient_class: String,
    pub legal_basis_ref: String,
    pub dpv_profile_ref: String,
    pub safeguards: Vec<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetadataVisibility {
    pub service: Visibility,
    pub resources: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statistical_datasets: Option<Visibility>,
    pub semantics: Visibility,
    pub classifications: Visibility,
    pub processing: Visibility,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    Public,
    OperationBound,
    OperatorOnly,
}

/// Deployment-local bindings. No governed field is accepted here.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayRuntime {
    pub api_version: String,
    pub kind: String,
    pub server: ServerRuntime,
    pub package_path: String,
    pub sources: OrderedMap<RuntimeSource>,
    pub authentication: AuthenticationRuntime,
    pub audit: AuditRuntime,
    #[serde(default)]
    pub cursor: Option<CursorRuntime>,
    pub limits: RuntimeLimits,
    #[serde(default)]
    pub quotas: Option<QuotaRuntime>,
    #[serde(default)]
    pub shutdown: Option<ShutdownRuntime>,
}

impl RelayRuntime {
    pub fn parse_yaml(input: &str) -> Result<Self, ContractParseError> {
        let runtime: Self =
            serde_norway::from_str(input).map_err(|source| ContractParseError { source })?;
        if runtime.is_valid() {
            Ok(runtime)
        } else {
            Err(ContractParseError {
                source: <serde_norway::Error as de::Error>::custom(
                    "the deployment binding violates the closed runtime profile",
                ),
            })
        }
    }

    fn is_valid(&self) -> bool {
        if self.api_version != "relay.registrystack.org/v2alpha1"
            || self.kind != "RelayRuntime"
            || self.server.bind.parse::<SocketAddr>().is_err()
            || self.package_path.trim().is_empty()
            || self.sources.is_empty()
            || self.audit.sink.trim().is_empty()
            || !valid_secret_reference(&self.audit.integrity_key_ref)
            || self.limits.request_timeout_milliseconds == 0
            || self.limits.request_timeout_milliseconds > 120_000
            || self.limits.concurrent_queries == 0
            || self.limits.concurrent_queries > 256
        {
            return false;
        }
        if self
            .sources
            .iter()
            .any(|(id, source)| !valid_runtime_id(id) || source.path.trim().is_empty())
        {
            return false;
        }
        if self.cursor.as_ref().is_some_and(|cursor| {
            !valid_secret_reference(&cursor.integrity_key_ref)
                || cursor.maximum_age_seconds == 0
                || cursor.maximum_age_seconds > 86_400
        }) {
            return false;
        }
        if self.quotas.as_ref().is_some_and(|quota| {
            quota.requests_per_minute == 0 || quota.burst == 0 || quota.burst > 100_000
        }) {
            return false;
        }
        if self
            .shutdown
            .as_ref()
            .is_some_and(|shutdown| shutdown.grace_period_milliseconds == 0)
        {
            return false;
        }
        self.authentication
            .issuer
            .as_ref()
            .is_none_or(|issuer| issuer.profile().is_some())
    }
}

fn valid_secret_reference(value: &str) -> bool {
    if let Some(name) = value.strip_prefix("secret:env/") {
        let bytes = name.as_bytes();
        return matches!(bytes.first(), Some(b'A'..=b'Z'))
            && bytes.len() <= 128
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_');
    }
    if let Some(name) = value.strip_prefix("secret:file/") {
        let bytes = name.as_bytes();
        return matches!(bytes.first(), Some(b'a'..=b'z'))
            && bytes.len() <= 128
            && bytes[1..].iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
    }
    false
}

fn valid_runtime_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerRuntime {
    pub bind: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeSource {
    pub path: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationRuntime {
    pub issuer: Option<IssuerRuntime>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssuerRuntime {
    pub id: String,
    /// Exact issuer accepted in access-token `iss` claims.
    ///
    /// Existing runtimes may omit this when `discoveryUrl` uses the canonical
    /// issuer origin. A distinct discovery transport or direct JWKS transport
    /// requires this field so network routing never changes token identity.
    #[serde(default)]
    pub trusted_issuer: Option<String>,
    #[serde(default)]
    pub discovery_url: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    pub audience: String,
    pub token_types: Vec<String>,
    pub algorithms: Vec<String>,
}

pub(crate) struct IssuerProfile {
    pub(crate) issuer_identifier: String,
    pub(crate) algorithm: IssuerAlgorithm,
    pub(crate) key_transport: IssuerKeyTransport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IssuerKeyTransport {
    Discovery(String),
    Jwks(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssuerAlgorithm {
    EdDsa,
    Es256,
    Rs256,
}

impl IssuerRuntime {
    pub(crate) fn profile(&self) -> Option<IssuerProfile> {
        self.profile_with_supervised_loopback(false)
    }

    #[cfg(feature = "tooling")]
    pub(crate) fn supervised_local_profile(&self) -> Option<IssuerProfile> {
        self.profile_with_supervised_loopback(true)
    }

    fn profile_with_supervised_loopback(
        &self,
        allow_supervised_loopback: bool,
    ) -> Option<IssuerProfile> {
        if !valid_runtime_id(&self.id)
            || self.audience.trim().is_empty()
            || self.audience.len() > MAXIMUM_ISSUER_AUDIENCE_BYTES
            || self.token_types.as_slice() != ["at+jwt"]
        {
            return None;
        }
        let algorithm = match self.algorithms.as_slice() {
            [algorithm] if algorithm == "EdDSA" => IssuerAlgorithm::EdDsa,
            [algorithm] if algorithm == "ES256" => IssuerAlgorithm::Es256,
            [algorithm] if algorithm == "RS256" => IssuerAlgorithm::Rs256,
            _ => return None,
        };
        let (issuer_identifier, key_transport) =
            match (self.discovery_url.as_deref(), self.jwks_url.as_deref()) {
                (Some(discovery_url), None) => {
                    let discovery_url =
                        canonical_issuer_transport_url(discovery_url, allow_supervised_loopback)?;
                    if !discovery_url.path().ends_with(OIDC_DISCOVERY_SUFFIX) {
                        return None;
                    }
                    let discovery_url = discovery_url.to_string();
                    let issuer_identifier = match self.trusted_issuer.as_deref() {
                        Some(issuer) => {
                            canonical_trusted_issuer(issuer, allow_supervised_loopback)?
                        }
                        None => discovery_url
                            .strip_suffix(OIDC_DISCOVERY_SUFFIX)?
                            .to_owned(),
                    };
                    (
                        issuer_identifier,
                        IssuerKeyTransport::Discovery(discovery_url),
                    )
                }
                (None, Some(jwks_url)) => {
                    let issuer_identifier = canonical_trusted_issuer(
                        self.trusted_issuer.as_deref()?,
                        allow_supervised_loopback,
                    )?;
                    let jwks_url =
                        canonical_issuer_transport_url(jwks_url, allow_supervised_loopback)?;
                    (
                        issuer_identifier,
                        IssuerKeyTransport::Jwks(jwks_url.to_string()),
                    )
                }
                _ => return None,
            };
        Some(IssuerProfile {
            issuer_identifier,
            algorithm,
            key_transport,
        })
    }
}

fn canonical_issuer_transport_url(raw: &str, allow_supervised_loopback: bool) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    let production_https = url.scheme() == "https";
    let supervised_loopback = allow_supervised_loopback
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0);
    if (!production_https && !supervised_loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.to_string() != raw
    {
        return None;
    }
    Some(url)
}

fn canonical_trusted_issuer(raw: &str, allow_supervised_loopback: bool) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let production_https = url.scheme() == "https";
    let supervised_loopback = allow_supervised_loopback
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0);
    if (!production_https && !supervised_loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let canonical = url.as_str();
    let canonical_root_without_slash =
        url.path() == "/" && canonical.strip_suffix('/') == Some(raw);
    (canonical == raw || canonical_root_without_slash).then(|| raw.to_owned())
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    pub sink: String,
    pub integrity_key_ref: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CursorRuntime {
    pub integrity_key_ref: String,
    pub maximum_age_seconds: u64,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeLimits {
    pub request_timeout_milliseconds: u64,
    pub concurrent_queries: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuotaRuntime {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShutdownRuntime {
    pub grace_period_milliseconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_map_rejects_duplicate_property_keys() {
        let input = r#"
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: x, version: v1, title: X}
registry:
  registryIdentifier: urn:x
  name: X
  authority: {identifier: urn:a, name: A}
  authoritativeScope: scope
  baseUri: https://example.invalid/
  identifierLifecyclePolicyRef: governance/id.yaml
  alignmentTargets: []
governance: {controller: urn:a, publisher: urn:a, auditOwner: urn:a}
semantics: {localVocabulary: https://example.invalid/vocab/}
classifications:
  privacy: {scheme: urn:p, version: "1"}
  institutional: {scheme: urn:i, version: "1"}
  handling: {scheme: urn:h, version: "1"}
  provenanceRef: governance/review.yaml
sources:
  db: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
resources:
  - id: thing
    datasetIdentifier: things
    entityTypeIdentifier: thing
    title: Thing
    description: Thing
    semanticClass: local:Thing
    source: {source: db, view: things}
    classificationDefaults: {privacy: public, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: id}
      revisionIdentifier: {sourceColumn: rev}
      lifecycleState: {sourceColumn: state, codelist: state.yaml}
      recordedAt: {sourceColumn: recorded_at}
    properties:
      name: {label: Name, description: Name, sourceColumn: name, type: string, sourceRequired: true, semanticTerm: "local:name"}
      name: {label: Other, description: Other, sourceColumn: other, type: string, sourceRequired: true, semanticTerm: "local:other"}
    disclosureProfiles: {default: {properties: [name]}}
    operations: {read: {access: public, disclosureProfile: default}}
metadataVisibility: {service: public, resources: public, semantics: public, classifications: public, processing: public}
"#;

        assert!(RegistryContract::parse_yaml(input).is_err());
    }

    #[test]
    fn runtime_rejects_governed_override() {
        let input = r#"
apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: /srv/relay/package
sources: {db: {path: /srv/registry.sqlite}}
authentication: {issuer: null}
audit: {sink: /var/log/relay.jsonl, integrityKeyRef: secret:key}
limits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 4}
disclosureProfiles: {}
"#;
        assert!(RelayRuntime::parse_yaml(input).is_err());
    }

    #[test]
    fn runtime_accepts_only_the_supported_secret_reference_grammars() {
        let template = |reference: &str| {
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:8080'}}\npackagePath: /srv/relay/package\nsources: {{db: {{path: /srv/registry.sqlite}}}}\nauthentication: {{issuer: null}}\naudit: {{sink: /var/log/relay.jsonl, integrityKeyRef: {reference}}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 4}}\n"
            )
        };
        for valid in ["secret:env/RELAY_KEY", "secret:file/audit-integrity-key"] {
            assert!(
                RelayRuntime::parse_yaml(&template(valid)).is_ok(),
                "{valid}"
            );
        }
        for invalid in [
            "secret:key",
            "secret:env/lowercase",
            "secret:env/KEY/value",
            "secret:file/../key",
            "secret:file/nested/key",
            "secret:vault/key",
        ] {
            assert!(
                RelayRuntime::parse_yaml(&template(invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn runtime_accepts_exactly_one_startup_supported_issuer_algorithm() {
        let runtime = |algorithms: &str| {
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:8080'}}\npackagePath: /srv/relay/package\nsources: {{db: {{path: /srv/registry.sqlite}}}}\nauthentication:\n  issuer:\n    id: issuer\n    discoveryUrl: https://issuer.example.invalid/.well-known/openid-configuration\n    audience: registry\n    tokenTypes: [at+jwt]\n    algorithms: {algorithms}\naudit: {{sink: /var/log/relay.jsonl, integrityKeyRef: secret:env/RELAY_KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 4}}\n"
            )
        };

        for algorithm in ["EdDSA", "ES256", "RS256"] {
            assert!(RelayRuntime::parse_yaml(&runtime(&format!("[{algorithm}]"))).is_ok());
        }
        assert!(RelayRuntime::parse_yaml(&runtime("[EdDSA, ES256]")).is_err());
    }

    #[test]
    fn issuer_audience_is_bounded_inside_the_authentication_envelope() {
        let runtime = |audience: &str| {
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:8080'}}\npackagePath: /srv/relay/package\nsources: {{db: {{path: /srv/registry.sqlite}}}}\nauthentication:\n  issuer:\n    id: issuer\n    discoveryUrl: https://issuer.example.invalid/.well-known/openid-configuration\n    audience: '{audience}'\n    tokenTypes: [at+jwt]\n    algorithms: [EdDSA]\naudit: {{sink: /var/log/relay.jsonl, integrityKeyRef: secret:env/RELAY_KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 4}}\n"
            )
        };

        let boundary = "a".repeat(MAXIMUM_ISSUER_AUDIENCE_BYTES);
        assert!(RelayRuntime::parse_yaml(&runtime(&boundary)).is_ok());
        assert!(
            RelayRuntime::parse_yaml(&runtime(&format!("{boundary}a"))).is_err(),
            "one audience byte above the ceiling must be refused"
        );

        let maximally_escaped = "\0".repeat(MAXIMUM_ISSUER_AUDIENCE_BYTES);
        let claims = serde_json::to_vec(&serde_json::json!({
            "aud": maximally_escaped,
            "exp": 2,
            "iat": 1,
            "iss": "https://issuer.example.invalid",
            "sub": "s"
        }))
        .expect("claims serialize");
        assert!(claims.len() < 64 * 1024);
        let encoded_claims_upper_bound = claims.len().div_ceil(3) * 4;
        assert!(encoded_claims_upper_bound + 16 * 1024 < 128 * 1024);
    }

    #[test]
    fn runtime_issuer_discovery_matches_the_exact_startup_profile() {
        let runtime = |discovery_url: &str| {
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:8080'}}\npackagePath: /srv/relay/package\nsources: {{db: {{path: /srv/registry.sqlite}}}}\nauthentication:\n  issuer:\n    id: issuer\n    discoveryUrl: {discovery_url}\n    audience: registry\n    tokenTypes: [at+jwt]\n    algorithms: [EdDSA]\naudit: {{sink: /var/log/relay.jsonl, integrityKeyRef: secret:env/RELAY_KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 4}}\n"
            )
        };
        let valid = "https://identity.example.invalid/.well-known/openid-configuration";
        let parsed = RelayRuntime::parse_yaml(&runtime(valid)).expect("exact discovery URL");
        assert_eq!(
            parsed
                .authentication
                .issuer
                .as_ref()
                .and_then(IssuerRuntime::profile)
                .map(|profile| profile.issuer_identifier),
            Some("https://identity.example.invalid".to_owned())
        );

        for invalid in [
            "https://operator:credential@identity.example.invalid/.well-known/openid-configuration",
            "https://identity.example.invalid/.well-known/openid-configuration?tenant=x",
            "https://identity.example.invalid/.well-known/openid-configuration#fragment",
            "https://identity.example.invalid/.well-known/oauth-authorization-server",
            "https:///.well-known/openid-configuration",
        ] {
            assert!(
                RelayRuntime::parse_yaml(&runtime(invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn runtime_separates_trusted_issuer_from_one_key_transport() {
        let runtime = |transport: &str| {
            format!(
                "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {{bind: '127.0.0.1:8080'}}\npackagePath: /srv/relay/package\nsources: {{db: {{path: /srv/registry.sqlite}}}}\nauthentication:\n  issuer:\n    id: issuer\n    trustedIssuer: https://issuer.example.invalid\n{transport}    audience: registry\n    tokenTypes: [at+jwt]\n    algorithms: [EdDSA]\naudit: {{sink: /var/log/relay.jsonl, integrityKeyRef: secret:env/RELAY_KEY}}\nlimits: {{requestTimeoutMilliseconds: 1000, concurrentQueries: 4}}\n"
            )
        };

        let discovery = RelayRuntime::parse_yaml(
            &runtime(
                "    discoveryUrl: https://discovery.example.invalid/.well-known/openid-configuration\n",
            ),
        )
        .expect("distinct discovery transport parses");
        let profile = discovery
            .authentication
            .issuer
            .as_ref()
            .and_then(IssuerRuntime::profile)
            .expect("distinct discovery transport validates");
        assert_eq!(profile.issuer_identifier, "https://issuer.example.invalid");
        assert_eq!(
            profile.key_transport,
            IssuerKeyTransport::Discovery(
                "https://discovery.example.invalid/.well-known/openid-configuration".to_owned()
            )
        );

        let jwks = RelayRuntime::parse_yaml(&runtime(
            "    jwksUrl: https://keys.example.invalid/issuer.jwks.json\n",
        ))
        .expect("direct JWKS transport parses");
        let profile = jwks
            .authentication
            .issuer
            .as_ref()
            .and_then(IssuerRuntime::profile)
            .expect("direct JWKS transport validates");
        assert_eq!(profile.issuer_identifier, "https://issuer.example.invalid");
        assert_eq!(
            profile.key_transport,
            IssuerKeyTransport::Jwks("https://keys.example.invalid/issuer.jwks.json".to_owned())
        );

        let root_jwks =
            RelayRuntime::parse_yaml(&runtime("    jwksUrl: https://keys.example.invalid/\n"))
                .expect("canonical root JWKS transport parses");
        assert_eq!(
            root_jwks
                .authentication
                .issuer
                .as_ref()
                .and_then(IssuerRuntime::profile)
                .expect("canonical root JWKS transport validates")
                .key_transport,
            IssuerKeyTransport::Jwks("https://keys.example.invalid/".to_owned())
        );

        for trusted_issuer in [
            "https://issuer.example.invalid/",
            "https://issuer.example.invalid/tenant/",
        ] {
            let trailing_slash =
                runtime("    jwksUrl: https://keys.example.invalid/issuer.jwks.json\n").replace(
                    "trustedIssuer: https://issuer.example.invalid",
                    &format!("trustedIssuer: {trusted_issuer}"),
                );
            let profile = RelayRuntime::parse_yaml(&trailing_slash)
                .expect("canonical trailing-slash issuer parses")
                .authentication
                .issuer
                .as_ref()
                .and_then(IssuerRuntime::profile)
                .expect("canonical trailing-slash issuer validates");
            assert_eq!(profile.issuer_identifier, trusted_issuer);
        }

        for invalid in [
            runtime(""),
            runtime(
                "    discoveryUrl: https://discovery.example.invalid/.well-known/openid-configuration\n    jwksUrl: https://keys.example.invalid/issuer.jwks.json\n",
            ),
            runtime("    jwksUrl: http://keys.example.invalid/issuer.jwks.json\n"),
        ] {
            assert!(
                RelayRuntime::parse_yaml(&invalid).is_err(),
                "runtime accepted an invalid issuer transport contract"
            );
        }

        let missing_trusted_issuer =
            runtime("    jwksUrl: https://keys.example.invalid/issuer.jwks.json\n")
                .replace("    trustedIssuer: https://issuer.example.invalid\n", "");
        assert!(RelayRuntime::parse_yaml(&missing_trusted_issuer).is_err());
    }

    #[test]
    fn cursor_requirement_counts_only_potentially_visible_metadata_resources() {
        let mut contract = RegistryContract::parse_yaml(crate::compiler::tests::valid_contract())
            .expect("base contract");
        let mut runtime = RelayRuntime::parse_yaml(
            "apiVersion: relay.registrystack.org/v2alpha1\nkind: RelayRuntime\nserver: {bind: '127.0.0.1:8080'}\npackagePath: package\nsources: {db: {path: fixture.sqlite}}\nauthentication: {issuer: null}\naudit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/KEY}\nlimits: {requestTimeoutMilliseconds: 1000, concurrentQueries: 1}\n",
        )
        .expect("runtime without cursor");
        let mut protected_resource = contract.resources[0].clone();
        protected_resource.id = "protected-record".into();
        protected_resource.operations.read = Some(
            serde_norway::from_str(
                "defaultAccessProfile: protected\naccessProfiles:\n  protected: {access: {scope: 'registry:record:read'}, disclosureProfile: public}\n",
            )
            .expect("protected read operation"),
        );
        contract.resources.push(protected_resource);

        assert!(runtime_cursor_configuration_is_valid(&contract, &runtime));

        contract.metadata_visibility.resources = Visibility::OperatorOnly;
        assert!(runtime_cursor_configuration_is_valid(&contract, &runtime));

        contract.metadata_visibility.resources = Visibility::OperationBound;
        assert!(!runtime_cursor_configuration_is_valid(&contract, &runtime));

        runtime.cursor = Some(CursorRuntime {
            integrity_key_ref: "secret:env/CURSOR_KEY".into(),
            maximum_age_seconds: 300,
        });
        assert!(runtime_cursor_configuration_is_valid(&contract, &runtime));
    }

    #[test]
    fn legacy_single_profile_operation_shape_is_not_accepted() {
        let yaml = crate::compiler::tests::valid_contract().replace(
            "        defaultAccessProfile: public\n        accessProfiles:\n          public: {access: public, disclosureProfile: public}",
            "        access: public\n        disclosureProfile: public",
        );
        assert!(RegistryContract::parse_yaml(&yaml).is_err());
    }

    #[test]
    fn old_representation_keys_are_rejected_without_aliases() {
        let yaml = crate::compiler::tests::valid_contract()
            .replace("defaultAccessProfile", "defaultRepresentation")
            .replace("accessProfiles", "representations");
        assert!(RegistryContract::parse_yaml(&yaml).is_err());
    }

    #[test]
    fn resource_dataset_and_entity_type_identifiers_are_required_not_inferred() {
        let yaml = crate::compiler::tests::valid_contract();
        for field in [
            "    datasetIdentifier: records\n",
            "    entityTypeIdentifier: record\n",
        ] {
            assert!(
                RegistryContract::parse_yaml(&yaml.replace(field, "")).is_err(),
                "missing {field:?} must fail strict authoring"
            );
        }
    }

    #[test]
    fn statistical_authoring_is_strict_and_roundtrips_without_binding_aliases() {
        let yaml = crate::compiler::tests::statistical_contract();
        let contract = RegistryContract::parse_yaml(yaml).expect("statistical contract parses");
        let serialized = serde_norway::to_string(&contract).expect("contract serializes");
        assert_eq!(
            RegistryContract::parse_yaml(&serialized).expect("serialized contract parses"),
            contract
        );
        assert_eq!(contract.statistical_datasets.len(), 1);

        for rejected in [
            yaml.replacen("statisticalDatasets:", "statisticalDataflows:", 1),
            yaml.replacen("    bindings: {sdmx: {}}\n", "    bindings: {}\n", 1),
            yaml.replacen(" granularity: annual,", "", 1),
        ] {
            assert!(
                RegistryContract::parse_yaml(&rejected).is_err(),
                "unsupported statistical authoring shape must be rejected"
            );
        }
    }
}
