// SPDX-License-Identifier: Apache-2.0
//! Operator-owned payment connections and their immutable attempt snapshots.

use registry_payment_protocol::Money;
use registry_payment_simulator_connector::SimulatorConnection;
use registry_platform_httputil::client::ServiceBaseUrl;
use registry_platform_yaml::SecretReference;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const API_VERSION: &str = "id.registrystack.org/formats/adapter/payments/v1alpha1";
pub const KIND: &str = "AdapterPayments";
pub const BILL_CONTRACT: &str = "service-fee-bill/v1";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/payments/payments.v1alpha1.schema.json";

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentsConfig {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    pub connections: Vec<PaymentConnection>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentConnection {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 128), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub institution_id: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 128), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub service_id: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64), extend("uniqueItems" = true)))]
    #[serde(deserialize_with = "unique_clients")]
    pub allowed_clients: Vec<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 128), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub required_scope: String,
    pub binding: PaymentBinding,
}

/// Persisted in full before a provider send. It holds credential references
/// and identities, never credential values. Rotation at the same reference is
/// supported; changing a reference does not reroute a retained attempt.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentBinding {
    #[cfg_attr(feature = "schema", schemars(extend("const" = true)))]
    pub simulation: bool,
    #[cfg_attr(feature = "schema", schemars(pattern("^[A-Z]{3}$")))]
    pub currency: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 0, max = 6)))]
    #[serde(deserialize_with = "currency_scale")]
    pub currency_scale: u8,
    pub provider: SimulatorConnection,
    pub provider_credential_ref: SecretReference,
    pub provider_credential_identity: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 86_400)))]
    #[serde(deserialize_with = "replay_window")]
    pub replay_window_seconds: u64,
    pub registry: RegistryBinding,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryBinding {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: String,
    pub record_type: String,
    pub record_route: String,
    pub read_profile: String,
    pub bind_profile: String,
    pub receipt_profile: String,
    pub bind_action: String,
    pub receipt_action: String,
    pub credential_ref: SecretReference,
    pub credential_identity: String,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("adapter.payment.configuration")]
pub struct ConfigError;

fn unique_clients<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    registry_platform_yaml::UniqueList::<String>::deserialize(deserializer)
        .map(|values| values.into_vec())
}

fn currency_scale<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    registry_platform_yaml::BoundedU32::<0, 6>::deserialize(deserializer)
        .map(|value| u8::try_from(value.get()).expect("the bounded scale fits in u8"))
}

fn replay_window<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    registry_platform_yaml::BoundedU64::<1, 86_400>::deserialize(deserializer)
        .map(|value| value.get())
}

impl PaymentsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.connections.is_empty() || self.connections.len() > 64 {
            return Err(ConfigError);
        }
        let mut ids = BTreeSet::new();
        for connection in &self.connections {
            if !connection_id(&connection.id)
                || !ids.insert(&connection.id)
                || !text(&connection.institution_id, 128)
                || !text(&connection.service_id, 128)
                || connection.allowed_clients.is_empty()
                || connection.allowed_clients.len() > 64
                || connection.allowed_clients.iter().any(|s| !text(s, 128))
                || connection
                    .allowed_clients
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != connection.allowed_clients.len()
                || !text(&connection.required_scope, 128)
            {
                return Err(ConfigError);
            }
            connection.binding.validate()?;
        }
        Ok(())
    }
}

impl PaymentBinding {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.simulation
            || !text(&self.provider_credential_identity, 128)
            || !(1..=86_400).contains(&self.replay_window_seconds)
        {
            return Err(ConfigError);
        }
        self.provider.validate().map_err(|_| ConfigError)?;
        Money {
            value: "1".into(),
            currency: self.currency.clone(),
            scale: self.currency_scale,
        }
        .minor_units()
        .map_err(|_| ConfigError)?;
        let registry = &self.registry;
        registry_platform_yaml::Url::new(registry.base_url.clone()).map_err(|_| ConfigError)?;
        ServiceBaseUrl::new(url::Url::parse(&registry.base_url).map_err(|_| ConfigError)?)
            .map_err(|_| ConfigError)?;
        if !text(&registry.read_profile, 128)
            || !text(&registry.bind_profile, 128)
            || !text(&registry.receipt_profile, 128)
            || !text(&registry.credential_identity, 128)
            || !local_id(&registry.record_route)
            || !local_id(&registry.record_type)
            || !local_id(&registry.bind_action)
            || !local_id(&registry.receipt_action)
            || registry.bind_action == registry.receipt_action
        {
            return Err(ConfigError);
        }
        Ok(())
    }

    pub fn revision(&self) -> Result<String, ConfigError> {
        let value = serde_json::json!({
            "connector": registry_payment_simulator_connector::CONNECTOR_VERSION,
            "billContract": BILL_CONTRACT, "binding": self,
        });
        let canonical =
            registry_platform_canonical_json::canonicalize_json(&value).map_err(|_| ConfigError)?;
        Ok(registry_platform_config::sha256_uri(&canonical))
    }
}

pub(crate) fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn local_id(value: &str) -> bool {
    text(value, 128)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn connection_id(value: &str) -> bool {
    registry_platform_yaml::LocalId::new(value).is_ok()
}
