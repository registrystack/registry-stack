// SPDX-License-Identifier: Apache-2.0
//! Operator-owned payment connections and their immutable attempt snapshots.

use registry_payment_mifos_connector::MifosConnection;
use registry_payment_protocol::Money;
use registry_payment_simulator_connector::SimulatorConnection;
use registry_platform_httputil::client::ServiceBaseUrl;
use registry_platform_yaml::SecretReference;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

use super::pack::{ConnectorKind, ProviderPackPin};

pub const API_VERSION: &str = "id.registrystack.org/formats/adapter/payments/v1alpha1";
pub const KIND: &str = "AdapterPayments";
pub const BILL_CONTRACT: &str = "service-fee-bill/v1";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/adapter/payments/payments.v1alpha1.schema.json";

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentsConfig {
    #[cfg_attr(feature = "schema", schemars(length(max = 64)))]
    pub connections: Vec<PaymentConnection>,
    #[cfg_attr(feature = "schema", schemars(length(max = 64)))]
    #[serde(default)]
    pub disbursements: Vec<super::g2p_config::G2pConnection>,
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
    /// Exact reviewed provider artifact used for new attempts. Older
    /// simulator-only configurations omit it; retained attempts keep their
    /// original binding unchanged across an upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_pack: Option<ProviderPackPin>,
    /// Collections are simulation-only; a live collection provider is refused.
    #[cfg_attr(feature = "schema", schemars(extend("const" = true)))]
    pub simulation: bool,
    #[cfg_attr(feature = "schema", schemars(pattern("^[A-Z]{3}$")))]
    pub currency: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 0, max = 6)))]
    #[serde(deserialize_with = "currency_scale")]
    pub currency_scale: u8,
    pub provider: registry_platform_config::Gated<CollectionProvider>,
    pub provider_credential_ref: SecretReference,
    pub provider_credential_identity: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 86_400)))]
    #[serde(deserialize_with = "replay_window")]
    pub replay_window_seconds: u64,
    pub registry: RegistryBinding,
}

/// Closed provider bindings for P2G collections, selected by the authored
/// `type` member. The shared tagged-union reader preserves source positions
/// for errors inside either strict variant (CFG-ID-7, CFG-SCHEMA-8).
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum CollectionProvider {
    Simulator {
        connection: SimulatorConnection,
    },
    Mifos {
        connection: MifosConnection,
        payer: MifosPayerMapping,
        transaction_type: MifosTransactionType,
    },
    Http {
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
        submit_base_url: String,
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
        status_base_url: String,
        settings: Value,
    },
}
registry_platform_yaml::tagged_union!(CollectionProvider);

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum CollectionProviderWire<'a> {
    Simulator {
        connection: &'a SimulatorConnection,
    },
    Mifos {
        connection: &'a MifosConnection,
        payer: &'a MifosPayerMapping,
        transaction_type: &'a MifosTransactionType,
    },
    Http {
        submit_base_url: &'a str,
        status_base_url: &'a str,
        settings: &'a Value,
    },
}

static ADAPTER_PAYMENT_SIMULATOR: registry_platform_config::DevelopmentSetting =
    registry_platform_config::DevelopmentSetting {
        code: "adapter.posture.payment-simulator",
        key: "provider",
        summary: "Collections are sent to a synthetic simulator",
        production: "Remove the simulator collection connection from the production configuration.",
    };

impl registry_platform_config::DevelopmentClass for CollectionProvider {
    const SETTINGS: &'static [&'static registry_platform_config::DevelopmentSetting] =
        &[&ADAPTER_PAYMENT_SIMULATOR];

    fn development_setting(&self) -> Option<&'static registry_platform_config::DevelopmentSetting> {
        match self {
            Self::Simulator { .. } => Some(&ADAPTER_PAYMENT_SIMULATOR),
            Self::Mifos { .. } | Self::Http { .. } => None,
        }
    }
}

impl Serialize for CollectionProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Simulator { connection } => CollectionProviderWire::Simulator { connection },
            Self::Mifos {
                connection,
                payer,
                transaction_type,
            } => CollectionProviderWire::Mifos {
                connection,
                payer,
                transaction_type,
            },
            Self::Http {
                submit_base_url,
                status_base_url,
                settings,
            } => CollectionProviderWire::Http {
                submit_base_url,
                status_base_url,
                settings,
            },
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MifosPayerMapping {
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub financial_address_key: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub payer_id_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MifosTransactionType {
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub scenario: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub sub_scenario: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub initiator: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub initiator_type: String,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(&'static str);

impl ConfigError {
    pub const INVALID: Self = Self("adapter.payment.configuration");
    /// Collections run only against the synthetic simulator until a live
    /// collection provider is verified end to end.
    pub const COLLECTION_SIMULATION_ONLY: Self = Self("adapter.payment.collection-simulation-only");

    pub const fn code(self) -> &'static str {
        self.0
    }
}

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
    pub fn validate(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<(), ConfigError> {
        self.validate_connections(development, false)
    }

    /// Validate the readable parts of an offline file. The loader reports
    /// every development-only provider that the check cannot inspect.
    pub fn validate_for_check(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<(), ConfigError> {
        self.validate_connections(development, true)
    }

    fn validate_connections(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
        offline: bool,
    ) -> Result<(), ConfigError> {
        if (self.connections.is_empty() && self.disbursements.is_empty())
            || self.connections.len() > 64
            || self.disbursements.len() > 64
        {
            return Err(ConfigError::INVALID);
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
                return Err(ConfigError::INVALID);
            }
            let binding = &connection.binding;
            binding.validate_members()?;
            match binding.provider(development) {
                Ok(provider) => binding.validate_collection_provider(provider)?,
                Err(_) if offline => {}
                Err(error) => return Err(error),
            }
        }
        for connection in &self.disbursements {
            if !ids.insert(&connection.id) {
                return Err(ConfigError::INVALID);
            }
            connection.validate()?;
        }
        Ok(())
    }
}

impl PaymentBinding {
    pub fn validate(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<(), ConfigError> {
        self.validate_members()?;
        self.validate_collection_provider(self.provider(development)?)
    }

    fn validate_collection_provider(
        &self,
        provider: &CollectionProvider,
    ) -> Result<(), ConfigError> {
        // Collections are simulation-only: the Mifos and mapped HTTP arms
        // remain parseable for retained attempts but cannot back a new
        // connection until a live collection provider is verified.
        match provider {
            CollectionProvider::Simulator { connection } if self.simulation => {
                connection.validate().map_err(|_| ConfigError::INVALID)?;
            }
            CollectionProvider::Simulator { .. }
            | CollectionProvider::Mifos { .. }
            | CollectionProvider::Http { .. } => {
                return Err(ConfigError::COLLECTION_SIMULATION_ONLY);
            }
        }
        Ok(())
    }

    fn validate_members(&self) -> Result<(), ConfigError> {
        if !text(&self.provider_credential_identity, 128)
            || !(1..=86_400).contains(&self.replay_window_seconds)
        {
            return Err(ConfigError::INVALID);
        }
        if self.provider_pack.as_ref().is_some_and(|pin| {
            pin.id.is_empty()
                || pin.version.is_empty()
                || pin.digest.len() != 71
                || !pin.digest.starts_with("sha256:")
                || !pin.digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(ConfigError::INVALID);
        }
        Money {
            value: "1".into(),
            currency: self.currency.clone(),
            scale: self.currency_scale,
        }
        .minor_units()
        .map_err(|_| ConfigError::INVALID)?;
        let registry = &self.registry;
        registry_platform_yaml::Url::new(registry.base_url.clone())
            .map_err(|_| ConfigError::INVALID)?;
        ServiceBaseUrl::new(url::Url::parse(&registry.base_url).map_err(|_| ConfigError::INVALID)?)
            .map_err(|_| ConfigError::INVALID)?;
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
            return Err(ConfigError::INVALID);
        }
        Ok(())
    }

    pub fn provider(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<&CollectionProvider, ConfigError> {
        self.provider
            .get(development)
            .map_err(|_| ConfigError(ADAPTER_PAYMENT_SIMULATOR.code))
    }

    pub fn revision(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<String, ConfigError> {
        let connector = match self.provider(development)? {
            CollectionProvider::Simulator { .. } => {
                registry_payment_simulator_connector::CONNECTOR_VERSION
            }
            CollectionProvider::Mifos { .. } => registry_payment_mifos_connector::CONNECTOR_PROFILE,
            CollectionProvider::Http { .. } => "adapter-payment-http/v1",
        };
        let value = serde_json::json!({
            "connector": connector,
            "billContract": BILL_CONTRACT, "binding": self,
        });
        let canonical = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| ConfigError::INVALID)?;
        Ok(registry_platform_config::sha256_uri(&canonical))
    }

    pub fn connector_kind(
        &self,
        development: Option<&registry_platform_config::DevelopmentWitness>,
    ) -> Result<ConnectorKind, ConfigError> {
        Ok(match self.provider(development)? {
            CollectionProvider::Simulator { .. } => ConnectorKind::SimulatorP2gV1,
            CollectionProvider::Mifos { .. } => ConnectorKind::MifosPhEeLegacyV1,
            CollectionProvider::Http { .. } => ConnectorKind::AdapterPaymentHttpV1,
        })
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
