// SPDX-License-Identifier: Apache-2.0
//! Immutable bill and provider facts retained for exact recovery.

use super::config::{CollectionProvider, PaymentBinding, PaymentConnection};
use super::provider_mapping::{PreparedProviderRequest, ProviderAcceptance};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_payment_mifos_connector::{
    CollectionCommand, ExactMoney, PartyIdentifier, TransactionType,
};
use registry_payment_protocol::{
    CollectionAccepted, CollectionState, CollectionStatus, Money, PaymentProblemCode,
    RegistryReceipt, MAX_MINOR_UNITS,
};
use registry_payment_simulator_connector::{Observation, ProviderCommand as SimulatorCommand};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BillSnapshot {
    pub bill_id: Uuid,
    pub bill_version: u64,
    pub bill_digest: String,
    pub institution_id: String,
    pub service_id: String,
    pub request_id: String,
    pub tariff_id: String,
    pub tariff_version: u64,
    pub tariff_digest: String,
    pub payer_id: String,
    pub payer_financial_address: String,
    pub money: Money,
    pub simulation: bool,
}

impl BillSnapshot {
    pub fn validate_for(&self, connection: &PaymentConnection) -> Result<(), PaymentProblemCode> {
        if self.bill_id.is_nil()
            || self.bill_version == 0
            || self.bill_version > MAX_MINOR_UNITS
            || self.institution_id != connection.institution_id
            || self.service_id != connection.service_id
            || self.simulation != connection.binding.simulation
            || self.money.currency != connection.binding.currency
            || self.money.scale != connection.binding.currency_scale
            || !super::config::text(&self.bill_digest, 64)
            || self.bill_digest.len() != 64
            || !super::config::text(&self.request_id, 128)
            || !super::config::text(&self.tariff_id, 128)
            || !super::config::text(&self.tariff_digest, 64)
            || self.tariff_digest.len() != 64
            || self.tariff_version == 0
            || self.tariff_version > MAX_MINOR_UNITS
            || !super::config::text(&self.payer_id, 128)
            || !super::config::text(&self.payer_financial_address, 30)
        {
            return Err(PaymentProblemCode::Conflict);
        }
        self.money
            .minor_units()
            .map_err(|_| PaymentProblemCode::Conflict)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String, PaymentProblemCode> {
        digest(self)
    }

    /// Stable across independent Adapter stores. The complete bill and logical
    /// provider namespace bind the command; credentials and replay policy do not
    /// create another financial identity. The persisted command is never edited.
    pub fn provider_command(
        &self,
        binding: &PaymentBinding,
    ) -> Result<CollectionProviderCommand, PaymentProblemCode> {
        match &binding.provider {
            CollectionProvider::Simulator { connection } => {
                let origin = url::Url::parse(&connection.base_url)
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let identity = serde_json::json!({
                    "domain": "registry-adapter/payment-provider-command/v1",
                    "provider": {
                        "origin": origin.as_str(),
                        "producer": binding.provider_credential_identity,
                        "tenant": connection.tenant,
                        "biller": connection.biller,
                    },
                    "bill": self,
                });
                let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let digest = Sha256::digest(canonical);
                // Disjoint digest portions retain 180 bits across the bounded wire tuple.
                // A requestId collision with a different body must remain a provider conflict.
                let mut number = [0_u8; 8];
                number[1..].copy_from_slice(&digest[16..23]);
                let command = SimulatorCommand {
                    request_id: URL_SAFE_NO_PAD.encode(&digest[..9]),
                    bill_id: URL_SAFE_NO_PAD.encode(&digest[9..16]),
                    rtp_id: (u64::from_be_bytes(number) & ((1_u64 << 52) - 1)) + 1,
                    payer_address: self.payer_financial_address.clone(),
                    money: self.money.clone(),
                };
                command
                    .validate()
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                Ok(CollectionProviderCommand::Simulator(command))
            }
            CollectionProvider::Mifos {
                connection,
                payer,
                transaction_type,
            } => {
                let channel = url::Url::parse(&connection.channel_base_url)
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let operations = url::Url::parse(&connection.operations_base_url)
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let identity = serde_json::json!({
                    "domain": "registry-adapter/mifos-collection-command/v1",
                    "provider": {
                        "connector": registry_payment_mifos_connector::CONNECTOR_PROFILE,
                        "providerPack": binding.provider_pack,
                        "channelOrigin": channel.as_str(),
                        "operationsOrigin": operations.as_str(),
                        "producer": binding.provider_credential_identity,
                        "tenant": connection.tenant,
                        "paymentScheme": connection.payment_scheme,
                        "payer": payer,
                        "transactionType": transaction_type,
                    },
                    "bill": self,
                });
                let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let digest = Sha256::digest(canonical);
                let money = self
                    .money
                    .canonical()
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                let command = CollectionCommand {
                    correlation_id: URL_SAFE_NO_PAD.encode(&digest[..18]),
                    payer: [
                        PartyIdentifier {
                            key: payer.financial_address_key.clone(),
                            value: self.payer_financial_address.clone(),
                        },
                        PartyIdentifier {
                            key: payer.payer_id_key.clone(),
                            value: self.payer_id.clone(),
                        },
                    ],
                    money: ExactMoney {
                        amount: money.value,
                        currency: money.currency,
                    },
                    transaction_type: TransactionType {
                        scenario: transaction_type.scenario.clone(),
                        sub_scenario: transaction_type.sub_scenario.clone(),
                        initiator: transaction_type.initiator.clone(),
                        initiator_type: transaction_type.initiator_type.clone(),
                    },
                };
                command
                    .validate()
                    .map_err(|_| PaymentProblemCode::Unavailable)?;
                Ok(CollectionProviderCommand::Mifos(command))
            }
            CollectionProvider::Http { .. } => Err(PaymentProblemCode::Unavailable),
        }
    }

    /// Host-owned collection intent supplied to a reviewed pure mapping. The
    /// correlation binds the complete authoritative bill, fixed provider
    /// origins, operator settings, producer identity and provider pack. The
    /// mapping never receives credentials or chooses transport authority.
    pub fn http_intent(&self, binding: &PaymentBinding) -> Result<Value, PaymentProblemCode> {
        let CollectionProvider::Http {
            submit_base_url,
            status_base_url,
            settings,
        } = &binding.provider
        else {
            return Err(PaymentProblemCode::Unavailable);
        };
        let provider_pack = binding
            .provider_pack
            .as_ref()
            .ok_or(PaymentProblemCode::Unavailable)?;
        let submit =
            url::Url::parse(submit_base_url).map_err(|_| PaymentProblemCode::Unavailable)?;
        let status =
            url::Url::parse(status_base_url).map_err(|_| PaymentProblemCode::Unavailable)?;
        let identity = serde_json::json!({
            "domain": "registry-adapter/http-collection-command/v1",
            "provider": {
                "providerPack": provider_pack,
                "submitOrigin": submit.as_str(),
                "statusOrigin": status.as_str(),
                "producer": binding.provider_credential_identity,
                "settings": settings,
            },
            "bill": self,
        });
        let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        let correlation_id = URL_SAFE_NO_PAD.encode(&Sha256::digest(canonical)[..18]);
        let minor_units = self
            .money
            .minor_units()
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        Ok(serde_json::json!({
            "correlationId": correlation_id,
            "payerFinancialAddress": self.payer_financial_address,
            "payerId": self.payer_id,
            "money": {
                "minorUnits": minor_units,
                "currency": self.money.currency,
                "scale": self.money.scale,
            },
        }))
    }
}

/// Exact retained input and POST request for the generic fixed-role HTTP
/// connector. `preparedSubmit` is mapped and canonicalized before the attempt
/// is reserved, then sent without evaluating the mapping again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpCollectionCommand {
    pub intent: Value,
    pub prepared_submit: PreparedProviderRequest,
}

/// Exact durable command for the selected provider. Untagged serialization
/// leaves all retained simulator attempts in their original wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CollectionProviderCommand {
    Simulator(SimulatorCommand),
    Mifos(CollectionCommand),
    Http(HttpCollectionCommand),
}

impl CollectionProviderCommand {
    pub fn validate(&self) -> Result<(), PaymentProblemCode> {
        match self {
            Self::Simulator(command) => command
                .validate()
                .map_err(|_| PaymentProblemCode::Unavailable),
            Self::Mifos(command) => command
                .validate()
                .map_err(|_| PaymentProblemCode::Unavailable),
            Self::Http(command) => {
                if command.prepared_submit.role
                    != super::provider_mapping::PaymentEndpointRole::CollectionSubmit
                    || command.prepared_submit.method
                        != super::provider_mapping::PaymentHttpMethod::Post
                    || command.prepared_submit.body.is_none()
                    || !command.intent.is_object()
                {
                    return Err(PaymentProblemCode::Unavailable);
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub const fn simulator(&self) -> Option<&SimulatorCommand> {
        match self {
            Self::Simulator(command) => Some(command),
            Self::Mifos(_) | Self::Http(_) => None,
        }
    }

    pub fn simulator_mut(&mut self) -> Option<&mut SimulatorCommand> {
        match self {
            Self::Simulator(command) => Some(command),
            Self::Mifos(_) | Self::Http(_) => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedRegistryAction {
    pub action: String,
    pub key: String,
    pub inputs: Map<String, Value>,
    pub evidence: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attempt {
    pub id: Uuid,
    pub connection: String,
    pub principal: String,
    pub bill: BillSnapshot,
    pub bill_snapshot_digest: String,
    pub binding: PaymentBinding,
    pub binding_revision: String,
    pub provider_command: CollectionProviderCommand,
    /// Digest of the exact generic prepared request, including canonical body
    /// bytes. Compiled connectors can still rederive their command directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_command_digest: Option<String>,
    pub bind_action: Option<PreparedRegistryAction>,
    pub bound: bool,
    pub first_send_at: Option<i64>,
    pub transfer_id: Option<String>,
    /// Full mapped acknowledgement for a generic provider. Compiled
    /// connectors need only their historical `transferId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_acceptance: Option<ProviderAcceptance>,
    pub observation: Option<Observation>,
    pub report_action: Option<PreparedRegistryAction>,
    pub receipt_digest: Option<String>,
    pub receipt: Option<RegistryReceipt>,
}

impl Attempt {
    pub fn acceptance(&self) -> CollectionAccepted {
        CollectionAccepted {
            collection_id: self.id,
            bill_id: self.bill.bill_id,
            bill_version: self.bill.bill_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.bill.simulation,
        }
    }

    pub fn status(&self) -> CollectionStatus {
        let (state, reference, failure) = self.observation.as_ref().map_or(
            (
                if self.transfer_id.is_some() {
                    CollectionState::Accepted
                } else {
                    CollectionState::Unknown
                },
                None,
                None,
            ),
            |o| {
                (
                    o.state,
                    o.provider_reference.clone(),
                    o.failure_reason.clone(),
                )
            },
        );
        CollectionStatus {
            collection_id: self.id,
            bill_id: self.bill.bill_id,
            bill_version: self.bill.bill_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.bill.simulation,
            state,
            money: self.bill.money.clone(),
            provider_reference: reference,
            failure_reason: failure,
        }
    }

    pub fn may_dispatch(&self, now: i64) -> Result<(), PaymentProblemCode> {
        if !self.bound {
            return Err(PaymentProblemCode::Conflict);
        }
        if let Some(first) = self.first_send_at {
            if matches!(
                &self.binding.provider,
                CollectionProvider::Mifos { .. } | CollectionProvider::Http { .. }
            ) {
                return Err(PaymentProblemCode::RecoveryHeld);
            }
            if now < first
                || u64::try_from(now - first).map_err(|_| PaymentProblemCode::RecoveryHeld)?
                    >= self.binding.replay_window_seconds
            {
                return Err(PaymentProblemCode::RecoveryHeld);
            }
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), PaymentProblemCode> {
        let command_matches = match (&self.binding.provider, &self.provider_command) {
            (CollectionProvider::Http { .. }, CollectionProviderCommand::Http(command)) => {
                command.intent == self.bill.http_intent(&self.binding)?
                    && self.binding.provider_pack.as_ref()
                        == Some(&command.prepared_submit.provider_pack)
                    && command
                        .prepared_submit
                        .validate_restored(
                            super::provider_mapping::PaymentEndpointRole::CollectionSubmit,
                            self.binding
                                .provider_pack
                                .as_ref()
                                .ok_or(PaymentProblemCode::Unavailable)?,
                        )
                        .is_ok()
                    && self.provider_command_digest.as_ref()
                        == Some(&digest(&self.provider_command)?)
            }
            (CollectionProvider::Http { .. }, _) | (_, CollectionProviderCommand::Http(_)) => false,
            _ => {
                self.provider_command_digest.is_none()
                    && self.provider_command == self.bill.provider_command(&self.binding)?
            }
        };
        if self
            .binding
            .revision()
            .map_err(|_| PaymentProblemCode::Unavailable)?
            != self.binding_revision
            || self.bill.digest()? != self.bill_snapshot_digest
            || self.bill.simulation != self.binding.simulation
            || !command_matches
            || self.provider_acceptance.as_ref().is_some_and(|acceptance| {
                self.transfer_id.is_none()
                    || acceptance.correlation_id
                        != self.provider_command.correlation_id().unwrap_or_default()
            })
        {
            return Err(PaymentProblemCode::Unavailable);
        }
        self.provider_command
            .validate()
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        self.status()
            .validate()
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        Ok(())
    }
}

impl CollectionProviderCommand {
    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        match self {
            Self::Simulator(_) => None,
            Self::Mifos(command) => Some(&command.correlation_id),
            Self::Http(command) => command.intent.get("correlationId")?.as_str(),
        }
    }
}

pub fn digest(value: &impl Serialize) -> Result<String, PaymentProblemCode> {
    let value = serde_json::to_value(value).map_err(|_| PaymentProblemCode::Unavailable)?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| PaymentProblemCode::Unavailable)?;
    Ok(registry_platform_config::sha256_uri(&bytes))
}
