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

/// A duplicate-free insertion-ordered YAML mapping.
///
/// Property and selector order is authored behavior, while ordinary map
/// containers would erase both duplicate keys and order before compilation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderedMap<T>(Vec<(String, T)>);

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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistryContract {
    pub api_version: String,
    pub kind: String,
    pub metadata: ContractMetadata,
    pub registry: RegistryDefinition,
    pub governance: Governance,
    pub semantics: Semantics,
    pub classifications: ClassificationCatalog,
    pub sources: OrderedMap<SourceDefinition>,
    pub resources: Vec<ResourceDefinition>,
    pub metadata_visibility: MetadataVisibility,
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
        || (!contract
            .resources
            .iter()
            .any(|resource| resource.operations.list.is_some())
            && contract
                .resources
                .iter()
                .filter(|resource| {
                    resource_can_appear_in_metadata(
                        resource,
                        contract.metadata_visibility.resources,
                    )
                })
                .take(2)
                .count()
                <= 1)
}

fn resource_can_appear_in_metadata(resource: &ResourceDefinition, visibility: Visibility) -> bool {
    if visibility == Visibility::OperatorOnly {
        return false;
    }
    resource
        .operations
        .list
        .iter()
        .flat_map(|operation| {
            operation
                .representations
                .iter()
                .map(|(_, item)| &item.access)
        })
        .chain(resource.operations.read.iter().flat_map(|operation| {
            operation
                .representations
                .iter()
                .map(|(_, item)| &item.access)
        }))
        .chain(resource.operations.lookups.iter().flat_map(|operation| {
            operation
                .representations
                .iter()
                .map(|(_, item)| &item.access)
        }))
        .any(|access| {
            visibility == Visibility::OperationBound || matches!(access, AccessRule::Public(_))
        })
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContractMetadata {
    pub id: String,
    pub version: String,
    pub title: String,
}

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Institution {
    pub identifier: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlignmentTarget {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub cfr_target: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Governance {
    pub controller: String,
    pub publisher: String,
    pub audit_owner: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Semantics {
    pub local_vocabulary: String,
    #[serde(default)]
    pub alignments: Vec<SemanticAlignment>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SemanticAlignment {
    pub id: String,
    pub version: String,
    pub profile_ref: String,
    pub digest: String,
    pub relation_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassificationCatalog {
    pub privacy: SchemeVersion,
    pub institutional: SchemeVersion,
    pub handling: SchemeVersion,
    pub provenance_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchemeVersion {
    pub scheme: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceDefinition {
    pub kind: String,
    pub profile: SourceProfile,
    pub expected_schema_fingerprint: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceProfile {
    Snapshot,
    LiveReadOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub id: String,
    pub title: String,
    pub description: String,
    pub semantic_class: String,
    pub source: ResourceSource,
    pub classification_defaults: ClassificationPartial,
    pub record_context: RecordContext,
    #[serde(default)]
    pub source_column_classifications: OrderedMap<ClassificationPartial>,
    pub properties: OrderedMap<PropertyDefinition>,
    pub disclosure_profiles: OrderedMap<DisclosureProfile>,
    pub operations: Operations,
    #[serde(default)]
    pub processing_descriptions: Vec<ProcessingDescription>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceSource {
    pub source: String,
    pub view: String,
}

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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Handling {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewStatus {
    Reviewed,
    Suggested,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordContext {
    pub record_identifier: ColumnBinding,
    pub revision_identifier: ColumnBinding,
    pub lifecycle_state: CodelistColumnBinding,
    pub recorded_at: ColumnBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ColumnBinding {
    pub source_column: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CodelistColumnBinding {
    pub source_column: String,
    pub codelist: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PropertyDefinition {
    pub label: String,
    pub description: String,
    pub source_column: String,
    #[serde(rename = "type")]
    pub data_type: DataType,
    #[serde(default)]
    pub codelist: Option<String>,
    pub source_required: bool,
    pub semantic_term: String,
    #[serde(default)]
    pub transform: Option<TransformDefinition>,
    #[serde(default)]
    pub classification: ClassificationPartial,
}

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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PartialStringReveal {
    Prefix,
    Suffix,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DateInputType {
    Date,
    DateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DatePrecision {
    Year,
    YearMonth,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DisclosureProfile {
    pub properties: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Operations {
    #[serde(default)]
    pub list: Option<ListOperation>,
    #[serde(default)]
    pub read: Option<RecordOperation>,
    #[serde(default)]
    pub lookups: Vec<LookupOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListOperation {
    pub default_representation: String,
    pub representations: OrderedMap<RepresentationDefinition>,
    #[serde(default)]
    pub filters: Vec<FilterDefinition>,
    pub allow_unfiltered: bool,
    pub order_by: Vec<String>,
    pub pagination: Pagination,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordOperation {
    pub default_representation: String,
    pub representations: OrderedMap<RepresentationDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupOperation {
    pub id: String,
    pub request_body: LookupRequestBody,
    pub default_representation: String,
    pub representations: OrderedMap<RepresentationDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RepresentationDefinition {
    pub access: AccessRule,
    pub disclosure_profile: String,
}

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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationMethod {
    Generated,
    Imported,
    Manual,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratedIdentificationBinding {
    pub report_ref: String,
    pub report_digest: String,
    pub rule_pack: RulePackBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RulePackBinding {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AccessRule {
    Public(String),
    Protected(ProtectedAccess),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtectedAccess {
    pub scope: String,
    #[serde(default)]
    pub purpose: Option<PurposeConstraint>,
    #[serde(default)]
    pub authority_row_binding: Option<AuthorityRowBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PurposeConstraint {
    pub claim: String,
    pub allowed: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AuthorityRowBinding {
    Claim(ClaimRowBinding),
    Principal(PrincipalRowBinding),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClaimRowBinding {
    pub claim: String,
    pub source_column: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrincipalRowBinding {
    pub principal: bool,
    pub source_column: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FilterDefinition {
    pub name: String,
    pub property: String,
    #[serde(rename = "type")]
    pub data_type: DataType,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pagination {
    pub default_page_size: u32,
    pub maximum_page_size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LookupRequestBody {
    pub maximum_bytes: u32,
    pub selectors: OrderedMap<SelectorDefinition>,
}

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetadataVisibility {
    pub service: Visibility,
    pub resources: Visibility,
    pub semantics: Visibility,
    pub classifications: Visibility,
    pub processing: Visibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    Public,
    OperationBound,
    OperatorOnly,
}

/// Deployment-local bindings. No governed field is accepted here.
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerRuntime {
    pub bind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeSource {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationRuntime {
    pub issuer: Option<IssuerRuntime>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssuerRuntime {
    pub id: String,
    pub discovery_url: String,
    pub audience: String,
    pub token_types: Vec<String>,
    pub algorithms: Vec<String>,
}

pub(crate) struct IssuerProfile {
    pub(crate) issuer_identifier: String,
    pub(crate) algorithm: IssuerAlgorithm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssuerAlgorithm {
    EdDsa,
    Es256,
    Rs256,
}

impl IssuerRuntime {
    pub(crate) fn profile(&self) -> Option<IssuerProfile> {
        if !valid_runtime_id(&self.id)
            || self.audience.trim().is_empty()
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
        let discovery_url = Url::parse(&self.discovery_url).ok()?;
        if discovery_url.scheme() != "https"
            || discovery_url.host_str().is_none()
            || !discovery_url.username().is_empty()
            || discovery_url.password().is_some()
            || discovery_url.query().is_some()
            || discovery_url.fragment().is_some()
            || !discovery_url.path().ends_with(OIDC_DISCOVERY_SUFFIX)
        {
            return None;
        }
        let canonical_discovery_url = discovery_url.to_string();
        if canonical_discovery_url != self.discovery_url {
            return None;
        }
        let issuer_identifier = canonical_discovery_url
            .strip_suffix(OIDC_DISCOVERY_SUFFIX)?
            .to_owned();
        if issuer_identifier.is_empty() || issuer_identifier.ends_with('/') {
            return None;
        }
        Some(IssuerProfile {
            issuer_identifier,
            algorithm,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    pub sink: String,
    pub integrity_key_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CursorRuntime {
    pub integrity_key_ref: String,
    pub maximum_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeLimits {
    pub request_timeout_milliseconds: u64,
    pub concurrent_queries: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QuotaRuntime {
    pub requests_per_minute: u32,
    pub burst: u32,
}

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
                "defaultRepresentation: protected\nrepresentations:\n  protected: {access: {scope: 'registry:record:read'}, disclosureProfile: public}\n",
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
            "        defaultRepresentation: public\n        representations:\n          public: {access: public, disclosureProfile: public}",
            "        access: public\n        disclosureProfile: public",
        );
        assert!(RegistryContract::parse_yaml(&yaml).is_err());
    }
}
