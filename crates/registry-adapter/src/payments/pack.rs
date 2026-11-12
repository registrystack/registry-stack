// SPDX-License-Identifier: Apache-2.0
//! Reviewed provider selection for the typed payment host.

use registry_adapter_core::{RhaiExpression, ScriptReference};
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, Report, UniqueList,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const API_VERSION: &str = "id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1";
pub const KIND: &str = "AdapterPaymentProviderPack";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/payment-provider-pack/payment-provider-pack.v1alpha1.schema.json";

const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentProviderPack {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub version: String,
    pub connector: ConnectorKind,
    #[cfg_attr(feature = "schema", schemars(length(min = 1), extend("uniqueItems" = true)))]
    pub capabilities: Vec<PaymentCapability>,
    #[serde(default)]
    pub tested_versions: Vec<String>,
    /// Pure, digest-pinned provider wire mappings. Compiled connectors omit
    /// this member; the generic HTTP connector requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<PaymentProviderMapping>,
}

/// Reader-only types apply the shared authored constraints while preserving
/// the public pack model and its generated schema.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PaymentProviderPackReader {
    id: String,
    version: String,
    connector: ConnectorKind,
    capabilities: UniqueList<PaymentCapability>,
    #[serde(default)]
    tested_versions: Vec<String>,
    #[serde(default)]
    mapping: Option<PaymentProviderMapping>,
}

impl From<PaymentProviderPackReader> for PaymentProviderPack {
    fn from(reader: PaymentProviderPackReader) -> Self {
        Self {
            id: reader.id,
            version: reader.version,
            connector: reader.connector,
            capabilities: reader.capabilities.into_vec(),
            tested_versions: reader.tested_versions,
            mapping: reader.mapping,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ConnectorKind {
    #[serde(rename = "simulator-p2g/v1")]
    SimulatorP2gV1,
    #[serde(rename = "mifos-ph-ee-legacy/v1")]
    MifosPhEeLegacyV1,
    /// One fixed-role HTTP transport whose provider-specific behavior is
    /// limited to the pack's pure request and response mappings.
    #[serde(rename = "adapter-payment-http/v1")]
    AdapterPaymentHttpV1,
}

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCapability {
    Collection,
    Disbursement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPackPin {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub version: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    pub digest: String,
}

/// The complete executable mapping closure of one data-driven provider.
/// Scripts are reviewed pack files, never deployment values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentProviderMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<PaymentOperationMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disbursement: Option<PaymentOperationMapping>,
    /// Every Rhai file reachable from the operation mappings, exactly once.
    pub scripts: Vec<ScriptReference>,
}

/// Submit and optional read-only status mappings for one typed payment
/// direction. The host fixes POST for submit and GET for status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentOperationMapping {
    /// Host-enforced credential mechanism for every endpoint in this payment
    /// direction. Scripts never receive or select credentials.
    pub auth: PaymentProviderAuth,
    pub submit: PaymentMappingCall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PaymentMappingCall>,
}

/// Closed credential mechanisms implemented by the fixed-role payment host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum PaymentProviderAuth {
    Bearer,
    MifosLegacySignature,
}

/// One pure mapping pair at a reviewed, origin-relative provider path.
/// Neither script can select an origin, endpoint role, method, credential, or
/// retry behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentMappingCall {
    pub path: String,
    pub request: RhaiExpression,
    pub response: RhaiExpression,
}

#[derive(Debug, thiserror::Error)]
#[error("adapter.payment.provider-pack-refused")]
pub struct PackError;

impl PaymentProviderPack {
    /// Decode one authored pack using the common strict YAML and envelope reader.
    pub fn from_yaml(bytes: &[u8]) -> Result<Self, Report> {
        Self::from_yaml_at("pack.yaml", bytes)
    }

    /// Decode one authored pack and retain the caller's displayed file path in
    /// every located diagnostic.
    pub fn from_yaml_at(file: impl Into<String>, bytes: &[u8]) -> Result<Self, Report> {
        let mut authored = AuthoredExpressions;
        let decoded = Reader::new(file)
            .with_hook(&mut authored)
            .decode::<PaymentProviderPackReader>(bytes, &Expect::one(&FORMAT))?;
        Ok(decoded.value.into())
    }

    pub fn validate(&self) -> Result<(), PackError> {
        let capabilities = self.capabilities.iter().copied().collect::<BTreeSet<_>>();
        if !local_id(&self.id)
            || self.version.is_empty()
            || self.version.len() > 64
            || self.capabilities.is_empty()
            || capabilities.len() != self.capabilities.len()
            || self.tested_versions.len() > 16
            || self
                .tested_versions
                .iter()
                .any(|version| version.is_empty() || version.len() > 128)
        {
            return Err(PackError);
        }
        if self.connector == ConnectorKind::SimulatorP2gV1
            && capabilities != BTreeSet::from([PaymentCapability::Collection])
        {
            return Err(PackError);
        }
        match (self.connector, &self.mapping) {
            (ConnectorKind::AdapterPaymentHttpV1, Some(mapping)) => {
                mapping.validate(&capabilities)?;
            }
            (ConnectorKind::AdapterPaymentHttpV1, None)
            | (ConnectorKind::SimulatorP2gV1 | ConnectorKind::MifosPhEeLegacyV1, Some(_)) => {
                return Err(PackError);
            }
            (ConnectorKind::SimulatorP2gV1 | ConnectorKind::MifosPhEeLegacyV1, None) => {}
        }
        Ok(())
    }

    pub fn check_pin(&self, pin: &ProviderPackPin, bytes: &[u8]) -> Result<(), PackError> {
        self.validate()?;
        if pin.id != self.id
            || pin.version != self.version
            || pin.digest != registry_platform_config::sha256_uri(bytes)
        {
            return Err(PackError);
        }
        Ok(())
    }
}

impl PaymentProviderMapping {
    fn validate(&self, capabilities: &BTreeSet<PaymentCapability>) -> Result<(), PackError> {
        if self.scripts.is_empty()
            || capabilities.contains(&PaymentCapability::Collection) != self.collection.is_some()
            || capabilities.contains(&PaymentCapability::Disbursement)
                != self.disbursement.is_some()
        {
            return Err(PackError);
        }

        let mut inventory = BTreeMap::new();
        for script in &self.scripts {
            if !relative_pack_path(&script.path)
                || inventory
                    .insert(script.path.as_str(), script.digest.as_str())
                    .is_some()
            {
                return Err(PackError);
            }
        }
        let mut referenced = BTreeSet::new();
        for operation in self.collection.iter().chain(self.disbursement.iter()) {
            for call in std::iter::once(&operation.submit).chain(operation.status.iter()) {
                provider_path_parameters(&call.path)?;
                for expression in [&call.request, &call.response] {
                    if !function_name(&expression.entrypoint)
                        || !inventory.contains_key(expression.file.as_str())
                    {
                        return Err(PackError);
                    }
                    referenced.insert(expression.file.as_str());
                }
            }
        }
        if referenced != inventory.keys().copied().collect() {
            return Err(PackError);
        }
        Ok(())
    }
}

pub(crate) fn provider_path_parameters(path: &str) -> Result<BTreeSet<String>, PackError> {
    validate_provider_path(path)?;
    let mut parameters = BTreeSet::new();
    let mut rest = path;
    while let Some(start) = rest.find("{{") {
        if rest[..start].contains('{') || rest[..start].contains('}') {
            return Err(PackError);
        }
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(PackError);
        };
        let name = &after[..end];
        if !path_parameter_name(name) || !parameters.insert(name.to_owned()) {
            return Err(PackError);
        }
        rest = &after[end + 2..];
    }
    if rest.contains("}}") || rest.contains('{') || rest.contains('}') {
        return Err(PackError);
    }
    Ok(parameters)
}

fn validate_provider_path(path: &str) -> Result<(), PackError> {
    if path.is_empty()
        || path.len() > 2_048
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.contains("\\")
        || path.bytes().any(|byte| byte.is_ascii_control())
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return Err(PackError);
    }
    // Also validates the complete placeholder grammar.
    let mut rest = path;
    while let Some(start) = rest.find("{{") {
        if rest[..start].contains('{') || rest[..start].contains('}') {
            return Err(PackError);
        }
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(PackError);
        };
        if !path_parameter_name(&after[..end]) {
            return Err(PackError);
        }
        rest = &after[end + 2..];
    }
    if rest.contains("}}") || rest.contains('{') || rest.contains('}') {
        return Err(PackError);
    }
    Ok(())
}

fn relative_pack_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn function_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn path_parameter_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric())
}

fn local_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
