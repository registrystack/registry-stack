// SPDX-License-Identifier: Apache-2.0
//! Typed structure and schemas for Python service read-back formats.

use std::{collections::BTreeMap, hash::Hash};

use platform_config::SecretProvidersConfig;
use registry_platform_yaml::{
    ApiVersion, BoundedU64, Decoded, DisplayText, EnvelopeRule, Expect, ExternalId, FormatSpec,
    Reader, Report, SecretReference, Severity, UniqueList, Url,
};
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;
use yaml_core as registry_platform_yaml;

pub const PYTHON_CONNECTION_API_VERSION: &str =
    "id.registrystack.org/formats/platform/python-connection/v1alpha1";
pub const PYTHON_CONNECTION_KIND: &str = "PlatformPythonConnection";
pub const PYTHON_CONNECTION_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/python-connection/python-connection.v1alpha1.schema.json";
pub const PYTHON_CONNECTION_SCHEMA_FILE: &str = "python-connection.v1alpha1.schema.json";
pub const DEV_WORKLOAD_TOKEN_API_VERSION: &str =
    "id.registrystack.org/formats/platform/dev-workload-token/v1alpha1";
pub const DEV_WORKLOAD_TOKEN_KIND: &str = "PlatformDevWorkloadToken";
pub const DEV_WORKLOAD_TOKEN_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/dev-workload-token/dev-workload-token.v1alpha1.schema.json";
pub const DEV_WORKLOAD_TOKEN_SCHEMA_FILE: &str = "dev-workload-token.v1alpha1.schema.json";
pub const DEV_PICKER_DESCRIPTOR_API_VERSION: &str =
    "id.registrystack.org/formats/platform/dev-picker-descriptor/v1alpha1";
pub const DEV_PICKER_DESCRIPTOR_KIND: &str = "PlatformDevPickerDescriptor";
pub const DEV_PICKER_DESCRIPTOR_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/dev-picker-descriptor/dev-picker-descriptor.v1alpha1.schema.json";
pub const DEV_PICKER_DESCRIPTOR_SCHEMA_FILE: &str = "dev-picker-descriptor.v1alpha1.schema.json";
pub const DEV_PICKER_TOKEN_API_VERSION: &str =
    "id.registrystack.org/formats/platform/dev-picker-token/v1alpha1";
pub const DEV_PICKER_TOKEN_KIND: &str = "PlatformDevPickerToken";
pub const DEV_PICKER_TOKEN_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/dev-picker-token/dev-picker-token.v1alpha1.schema.json";
pub const DEV_PICKER_TOKEN_SCHEMA_FILE: &str = "dev-picker-token.v1alpha1.schema.json";
pub const DEV_PICKER_GENERATION_API_VERSION: &str =
    "id.registrystack.org/formats/platform/dev-picker-generation/v1alpha1";
pub const DEV_PICKER_GENERATION_KIND: &str = "PlatformDevPickerGeneration";
pub const DEV_PICKER_GENERATION_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/dev-picker-generation/dev-picker-generation.v1alpha1.schema.json";
pub const DEV_PICKER_GENERATION_SCHEMA_FILE: &str = "dev-picker-generation.v1alpha1.schema.json";

pub const PYTHON_CONNECTION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: PYTHON_CONNECTION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(PYTHON_CONNECTION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

pub const DEV_WORKLOAD_TOKEN_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DEV_WORKLOAD_TOKEN_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DEV_WORKLOAD_TOKEN_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

pub const DEV_PICKER_DESCRIPTOR_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DEV_PICKER_DESCRIPTOR_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DEV_PICKER_DESCRIPTOR_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

pub const DEV_PICKER_TOKEN_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DEV_PICKER_TOKEN_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DEV_PICKER_TOKEN_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

pub const DEV_PICKER_GENERATION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DEV_PICKER_GENERATION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DEV_PICKER_GENERATION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAudience {
    Service,
    Holder,
    Staff,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadProduct {
    Breg,
    Messaging,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
pub enum TokenAlgorithm {
    EdDSA,
    ES256,
    ES384,
    RS256,
    RS384,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineAdmission {
    pub issuer: Url,
    pub resource: ExternalId,
    pub client_id: ExternalId,
    pub profile: ExternalId,
    #[serde(deserialize_with = "non_empty_unique_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub required_scopes: UniqueList<ExternalId>,
    #[serde(deserialize_with = "non_empty_map")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub required_claims: BTreeMap<ExternalId, ExternalId>,
    pub algorithm: TokenAlgorithm,
    pub access_token_type: ExternalId,
    pub maximum_access_token_lifetime_seconds: BoundedU64<1, 7200>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub jwks_uri: Option<Url>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub clock_skew_seconds: Option<BoundedU64<0, 300>>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_insecure_http: Option<bool>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(
        !remote,
        tag = "type",
        rename_all = "kebab-case",
        rename_all_fields = "camelCase"
    )
)]
#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WorkloadCredential {
    PrivateKeyJwt {
        issuer: Url,
        subject: ExternalId,
        token_endpoint: Url,
        client_id: ExternalId,
        profile: ExternalId,
        client_key_ref: SecretReference,
        resource: ExternalId,
        #[serde(deserialize_with = "non_empty_unique_list")]
        #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
        scopes: UniqueList<ExternalId>,
        #[cfg_attr(feature = "schema", schemars(schema_with = "authority_claims_schema"))]
        claims: BTreeMap<ExternalId, Value>,
    },
    RunnerToken {
        token_ref: SecretReference,
        run_id: ExternalId,
        binding: ExternalId,
        issuer: Url,
        subject: ExternalId,
        client_id: ExternalId,
        profile: ExternalId,
        resource: ExternalId,
        #[serde(deserialize_with = "non_empty_unique_list")]
        #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
        scopes: UniqueList<ExternalId>,
        #[cfg_attr(feature = "schema", schemars(schema_with = "authority_claims_schema"))]
        claims: BTreeMap<ExternalId, Value>,
        run_expires_at: BoundedU64<1, { u64::MAX }>,
    },
}
yaml_core::tagged_union!(WorkloadCredential, tag = "type");

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadBinding {
    #[cfg_attr(
        feature = "schema",
        schemars(regex(pattern = "^[a-z][a-z0-9-]{0,63}$"))
    )]
    pub name: String,
    pub product: WorkloadProduct,
    pub url: Url,
    pub default: bool,
    pub credential: WorkloadCredential,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PythonConnection {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 512)))]
    pub service: String,
    pub audience: ServiceAudience,
    pub secret_providers: SecretProvidersConfig,
    pub bindings: Vec<WorkloadBinding>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub admission: Option<MachineAdmission>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadTokenStatus {
    Stopped,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevWorkloadToken {
    pub run_id: ExternalId,
    pub binding: ExternalId,
    pub product: WorkloadProduct,
    pub issuer: Url,
    pub subject: ExternalId,
    pub client_id: ExternalId,
    pub profile: ExternalId,
    pub resource: ExternalId,
    #[serde(deserialize_with = "non_empty_unique_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub scopes: UniqueList<ExternalId>,
    #[cfg_attr(feature = "schema", schemars(schema_with = "authority_claims_schema"))]
    pub claims: BTreeMap<ExternalId, Value>,
    pub generation: BoundedU64<1, { u64::MAX }>,
    pub issued_at: BoundedU64<0, { u64::MAX }>,
    pub expires_at: BoundedU64<0, { u64::MAX }>,
    pub run_expires_at: BoundedU64<1, { u64::MAX }>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub status: Option<WorkloadTokenStatus>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 8192), regex(pattern = "^\\S+$"))
    )]
    pub token: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerPersona {
    Holder,
    Staff,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerProduct {
    Breg,
    Casework,
    Messaging,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerPersonProduct {
    Breg,
    Casework,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerWorkloadProduct {
    Breg,
    Messaging,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerProductTarget {
    pub url: Url,
    pub resource: ExternalId,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerCredential {
    pub token_file: ExternalId,
    pub profile: ExternalId,
    pub resource: ExternalId,
    #[serde(deserialize_with = "picker_audiences")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 4)))]
    pub audiences: UniqueList<ExternalId>,
    #[serde(deserialize_with = "picker_scopes")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub scopes: UniqueList<ExternalId>,
    pub principal_claim: ExternalId,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerPerson {
    #[serde(deserialize_with = "opaque_picker_value")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 20, max = 128),
            regex(pattern = "^[A-Za-z0-9_-]{20,128}$")
        )
    )]
    pub selector: String,
    #[serde(deserialize_with = "picker_label")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub label: String,
    pub subject: ExternalId,
    pub principal: ExternalId,
    pub client_id: ExternalId,
    #[serde(deserialize_with = "picker_credentials")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "picker_credentials_schema")
    )]
    pub credentials: BTreeMap<DevPickerPersonProduct, DevPickerCredential>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerWorkload {
    #[serde(deserialize_with = "picker_local_name")]
    #[cfg_attr(
        feature = "schema",
        schemars(regex(pattern = "^[a-z][a-z0-9-]{0,63}$"))
    )]
    pub name: String,
    pub product: DevPickerWorkloadProduct,
    pub default: bool,
    pub url: Url,
    pub issuer: Url,
    pub subject: ExternalId,
    pub client_id: ExternalId,
    pub profile: ExternalId,
    pub resource: ExternalId,
    #[serde(deserialize_with = "picker_scopes")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub scopes: UniqueList<ExternalId>,
    #[serde(deserialize_with = "picker_claims")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "picker_claims_schema"))]
    pub claims: BTreeMap<ExternalId, Value>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerDescriptor {
    #[serde(deserialize_with = "picker_run_id")]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 32, max = 32), regex(pattern = "^[0-9a-f]{32}$"))
    )]
    pub run_id: String,
    pub persona: DevPickerPersona,
    pub origin: Url,
    #[serde(deserialize_with = "opaque_picker_value")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 20, max = 128),
            regex(pattern = "^[A-Za-z0-9_-]{20,128}$")
        )
    )]
    pub session_namespace: String,
    pub issued_at: BoundedU64<1, { u64::MAX }>,
    pub expires_at: BoundedU64<1, { u64::MAX }>,
    pub generation_file: ExternalId,
    #[serde(deserialize_with = "picker_products")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "picker_products_schema"))]
    pub products: BTreeMap<DevPickerProduct, DevPickerProductTarget>,
    #[serde(deserialize_with = "picker_people")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub people: Vec<DevPickerPerson>,
    #[serde(
        default,
        deserialize_with = "present_external_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub workload_connection_file: Option<ExternalId>,
    #[serde(deserialize_with = "picker_workloads")]
    #[cfg_attr(feature = "schema", schemars(length(max = 32)))]
    pub workloads: Vec<DevPickerWorkload>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerTokenStatus {
    Stopped,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerToken {
    #[serde(deserialize_with = "picker_run_id")]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 32, max = 32), regex(pattern = "^[0-9a-f]{32}$"))
    )]
    pub run_id: String,
    pub picker: DevPickerPersona,
    pub persona: DevPickerPersona,
    #[serde(deserialize_with = "opaque_picker_value")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 20, max = 128),
            regex(pattern = "^[A-Za-z0-9_-]{20,128}$")
        )
    )]
    pub selector: String,
    pub product: DevPickerPersonProduct,
    pub issuer: Url,
    pub subject: ExternalId,
    pub principal: ExternalId,
    pub client_id: ExternalId,
    pub profile: ExternalId,
    pub resource: ExternalId,
    #[serde(deserialize_with = "picker_audiences")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 4)))]
    pub audiences: UniqueList<ExternalId>,
    #[serde(deserialize_with = "picker_scopes")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub scopes: UniqueList<ExternalId>,
    pub principal_claim: ExternalId,
    pub generation: BoundedU64<1, { u64::MAX }>,
    pub issued_at: BoundedU64<1, { u64::MAX }>,
    pub expires_at: BoundedU64<1, { u64::MAX }>,
    pub run_expires_at: BoundedU64<1, { u64::MAX }>,
    #[serde(
        default,
        deserialize_with = "present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub status: Option<DevPickerTokenStatus>,
    #[serde(
        default,
        deserialize_with = "present_bearer_token",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 8192), regex(pattern = "^\\S+$"))
    )]
    pub token: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevPickerGenerationStatus {
    Ready,
    Stopped,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevPickerGeneration {
    pub status: DevPickerGenerationStatus,
    #[serde(deserialize_with = "picker_run_id")]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 32, max = 32), regex(pattern = "^[0-9a-f]{32}$"))
    )]
    pub run_id: String,
    pub picker: DevPickerPersona,
    pub generation: BoundedU64<1, { u64::MAX }>,
    pub run_expires_at: BoundedU64<1, { u64::MAX }>,
}

fn non_empty_unique_list<'de, D, T>(deserializer: D) -> Result<UniqueList<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    let values = UniqueList::<T>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(de::Error::custom("must contain at least one item"));
    }
    Ok(values)
}

fn non_empty_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let values = BTreeMap::<K, V>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(de::Error::custom("must contain at least one member"));
    }
    Ok(values)
}

fn bounded_unique_list<'de, D, T, const MIN: usize, const MAX: usize>(
    deserializer: D,
) -> Result<UniqueList<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    let values = UniqueList::<T>::deserialize(deserializer)?;
    if !(MIN..=MAX).contains(&values.len()) {
        return Err(de::Error::custom("the list length is outside its bounds"));
    }
    Ok(values)
}

fn picker_audiences<'de, D>(deserializer: D) -> Result<UniqueList<ExternalId>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_list::<D, ExternalId, 1, 4>(deserializer)
}

fn picker_scopes<'de, D>(deserializer: D) -> Result<UniqueList<ExternalId>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_unique_list::<D, ExternalId, 1, 32>(deserializer)
}

fn bounded_map<'de, D, K, V, const MIN: usize, const MAX: usize>(
    deserializer: D,
) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let values = BTreeMap::<K, V>::deserialize(deserializer)?;
    if !(MIN..=MAX).contains(&values.len()) {
        return Err(de::Error::custom("the mapping size is outside its bounds"));
    }
    Ok(values)
}

fn picker_products<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<DevPickerProduct, DevPickerProductTarget>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_map::<D, DevPickerProduct, DevPickerProductTarget, 1, 3>(deserializer)
}

fn picker_credentials<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<DevPickerPersonProduct, DevPickerCredential>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_map::<D, DevPickerPersonProduct, DevPickerCredential, 1, 2>(deserializer)
}

fn picker_claims<'de, D>(deserializer: D) -> Result<BTreeMap<ExternalId, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_map::<D, ExternalId, Value, 0, 64>(deserializer)
}

fn bounded_vec<'de, D, T, const MIN: usize, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if !(MIN..=MAX).contains(&values.len()) {
        return Err(de::Error::custom("the list length is outside its bounds"));
    }
    Ok(values)
}

fn picker_people<'de, D>(deserializer: D) -> Result<Vec<DevPickerPerson>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_vec::<D, DevPickerPerson, 1, 32>(deserializer)
}

fn picker_workloads<'de, D>(deserializer: D) -> Result<Vec<DevPickerWorkload>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_vec::<D, DevPickerWorkload, 0, 32>(deserializer)
}

fn picker_run_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(de::Error::custom(
            "the run id must be 32 lowercase hexadecimal digits",
        ));
    }
    Ok(value)
}

fn opaque_picker_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if !(20..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(de::Error::custom("the opaque value has an invalid shape"));
    }
    Ok(value)
}

fn picker_local_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'a'..=b'z'))
        || bytes.len() > 64
        || !bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(de::Error::custom("the local name has an invalid shape"));
    }
    Ok(value)
}

fn picker_label<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = DisplayText::deserialize(deserializer)?.into_string();
    if value.is_empty()
        || value.chars().count() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(de::Error::custom("the display label has an invalid shape"));
    }
    Ok(value)
}

#[cfg(feature = "schema")]
fn authority_claims_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<ExternalId>(),
        "additionalProperties": true,
        "x-registry-passthrough": "Claim values are written into the workload token as declared.",
    })
}

#[cfg(feature = "schema")]
fn picker_products_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let _ = generator.subschema_for::<ExternalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": {
            "$ref": "#/$defs/ExternalId",
            "enum": ["breg", "casework", "messaging"],
        },
        "additionalProperties": generator.subschema_for::<DevPickerProductTarget>(),
        "minProperties": 1,
        "maxProperties": 3,
    })
}

#[cfg(feature = "schema")]
fn picker_credentials_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let _ = generator.subschema_for::<ExternalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": {
            "$ref": "#/$defs/ExternalId",
            "enum": ["breg", "casework"],
        },
        "additionalProperties": generator.subschema_for::<DevPickerCredential>(),
        "minProperties": 1,
        "maxProperties": 2,
    })
}

#[cfg(feature = "schema")]
fn picker_claims_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<ExternalId>(),
        "additionalProperties": true,
        "maxProperties": 64,
        "x-registry-passthrough": "Claim values are written into the workload token as declared.",
    })
}

fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn present_external_id<'de, D>(deserializer: D) -> Result<Option<ExternalId>, D::Error>
where
    D: Deserializer<'de>,
{
    ExternalId::deserialize(deserializer).map(Some)
}

fn present_bearer_token<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_whitespace) {
        return Err(de::Error::custom("the bearer token has an invalid shape"));
    }
    Ok(Some(value))
}

fn document_value<T>(decoded: Decoded<T>) -> Value {
    decoded.document.to_json_value()
}

pub fn read_python_connection(file: &str, bytes: &[u8]) -> Result<Value, Report> {
    Reader::new(file)
        .decode::<PythonConnection>(bytes, &Expect::one(&PYTHON_CONNECTION_FORMAT))
        .map(document_value)
}

pub fn read_dev_workload_token(file: &str, bytes: &[u8]) -> Result<Value, Report> {
    Reader::new(file)
        .decode::<DevWorkloadToken>(bytes, &Expect::one(&DEV_WORKLOAD_TOKEN_FORMAT))
        .map(document_value)
}

pub fn read_dev_picker_descriptor(file: &str, bytes: &[u8]) -> Result<Value, Report> {
    Reader::new(file)
        .decode::<DevPickerDescriptor>(bytes, &Expect::one(&DEV_PICKER_DESCRIPTOR_FORMAT))
        .map(document_value)
}

pub fn read_dev_picker_token(file: &str, bytes: &[u8]) -> Result<Value, Report> {
    let decoded = Reader::new(file)
        .decode::<DevPickerToken>(bytes, &Expect::one(&DEV_PICKER_TOKEN_FORMAT))?;
    if decoded.value.status.is_some() == decoded.value.token.is_some() {
        let pointer = if decoded.value.status.is_some() {
            "/status"
        } else {
            ""
        };
        let diagnostic = decoded.document.diagnostic_at_value(
            Severity::Error,
            "config.invalid-value",
            pointer,
            "the token document does not hold one supported credential state",
            "Write `token` for a ready credential, or `status: stopped` without `token`.",
        );
        return Err(decoded.document.report_with([diagnostic]));
    }
    Ok(decoded.document.to_json_value())
}

pub fn read_dev_picker_generation(file: &str, bytes: &[u8]) -> Result<Value, Report> {
    Reader::new(file)
        .decode::<DevPickerGeneration>(bytes, &Expect::one(&DEV_PICKER_GENERATION_FORMAT))
        .map(document_value)
}

#[cfg(feature = "schema")]
fn schema<T: schemars::JsonSchema>(api_version: &str, kind: &str, id: &str) -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema is JSON");
    schema["$id"] = Value::String(id.to_owned());
    schema["properties"]["apiVersion"] =
        serde_json::json!({"type": "string", "const": api_version});
    schema["properties"]["kind"] = serde_json::json!({"type": "string", "const": kind});
    let required = schema["required"]
        .as_array_mut()
        .expect("a document schema requires its members");
    required.insert(0, Value::String("kind".to_owned()));
    required.insert(0, Value::String("apiVersion".to_owned()));
    schema
}

#[cfg(feature = "schema")]
fn object_definition_mut<'a>(schema: &'a mut Value, name: &str) -> &'a mut Value {
    schema
        .get_mut("$defs")
        .and_then(Value::as_object_mut)
        .and_then(|definitions| definitions.get_mut(name))
        .unwrap_or_else(|| panic!("generated schema has no {name} definition"))
}

#[cfg(feature = "schema")]
fn refuse_null(schema: &mut Value) {
    let only_type = schema
        .get_mut("type")
        .and_then(Value::as_array_mut)
        .and_then(|types| {
            types.retain(|value| value != "null");
            if types.len() == 1 {
                Some(types[0].clone())
            } else {
                None
            }
        });
    if let Some(only_type) = only_type {
        schema["type"] = only_type;
    }
    let only_alternative = schema
        .get_mut("anyOf")
        .and_then(Value::as_array_mut)
        .and_then(|alternatives| {
            alternatives
                .retain(|alternative| alternative.get("type") != Some(&serde_json::json!("null")));
            if alternatives.len() == 1 {
                Some(alternatives[0].clone())
            } else {
                None
            }
        });
    if let Some(only_alternative) = only_alternative {
        *schema = only_alternative;
    }
}

#[cfg(feature = "schema")]
pub fn schema_documents() -> [(&'static str, Value); 5] {
    let mut connection = schema::<PythonConnection>(
        PYTHON_CONNECTION_API_VERSION,
        PYTHON_CONNECTION_KIND,
        PYTHON_CONNECTION_SCHEMA_ID,
    );
    object_definition_mut(&mut connection, "MachineAdmission")["properties"]["requiredClaims"]
        ["propertyNames"] = serde_json::json!({"$ref": "#/$defs/ExternalId"});
    object_definition_mut(&mut connection, "MachineAdmission")["properties"]["requiredClaims"]
        ["minProperties"] = serde_json::json!(1);
    for name in ["jwksUri", "clockSkewSeconds", "allowInsecureHttp"] {
        refuse_null(
            &mut object_definition_mut(&mut connection, "MachineAdmission")["properties"][name],
        );
    }
    refuse_null(&mut connection["properties"]["admission"]);
    let mut token = schema::<DevWorkloadToken>(
        DEV_WORKLOAD_TOKEN_API_VERSION,
        DEV_WORKLOAD_TOKEN_KIND,
        DEV_WORKLOAD_TOKEN_SCHEMA_ID,
    );
    token["oneOf"] = serde_json::json!([
        {"required": ["token"], "not": {"required": ["status"]}},
        {"required": ["status"], "not": {"required": ["token"]}}
    ]);
    token["properties"]["issuedAt"]["minimum"] = serde_json::json!(0);
    token["properties"]["expiresAt"]["minimum"] = serde_json::json!(0);
    token["properties"]["issuedAt"]
        .as_object_mut()
        .expect("issuedAt is an integer schema")
        .remove("format");
    token["properties"]["expiresAt"]
        .as_object_mut()
        .expect("expiresAt is an integer schema")
        .remove("format");
    refuse_null(&mut token["properties"]["status"]);
    refuse_null(&mut token["properties"]["token"]);
    let mut picker_descriptor = schema::<DevPickerDescriptor>(
        DEV_PICKER_DESCRIPTOR_API_VERSION,
        DEV_PICKER_DESCRIPTOR_KIND,
        DEV_PICKER_DESCRIPTOR_SCHEMA_ID,
    );
    refuse_null(&mut picker_descriptor["properties"]["workloadConnectionFile"]);
    let mut picker_token = schema::<DevPickerToken>(
        DEV_PICKER_TOKEN_API_VERSION,
        DEV_PICKER_TOKEN_KIND,
        DEV_PICKER_TOKEN_SCHEMA_ID,
    );
    picker_token["oneOf"] = serde_json::json!([
        {"required": ["token"], "not": {"required": ["status"]}},
        {"required": ["status"], "not": {"required": ["token"]}}
    ]);
    refuse_null(&mut picker_token["properties"]["status"]);
    refuse_null(&mut picker_token["properties"]["token"]);
    let picker_generation = schema::<DevPickerGeneration>(
        DEV_PICKER_GENERATION_API_VERSION,
        DEV_PICKER_GENERATION_KIND,
        DEV_PICKER_GENERATION_SCHEMA_ID,
    );
    [
        (PYTHON_CONNECTION_SCHEMA_FILE, connection),
        (DEV_WORKLOAD_TOKEN_SCHEMA_FILE, token),
        (DEV_PICKER_DESCRIPTOR_SCHEMA_FILE, picker_descriptor),
        (DEV_PICKER_TOKEN_SCHEMA_FILE, picker_token),
        (DEV_PICKER_GENERATION_SCHEMA_FILE, picker_generation),
    ]
}
