// SPDX-License-Identifier: Apache-2.0
//! Immutable bill and provider facts retained for exact recovery.

use super::config::{PaymentBinding, PaymentConnection};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_payment_protocol::{
    CollectionAccepted, CollectionState, CollectionStatus, Money, PaymentProblemCode,
    RegistryReceipt, MAX_MINOR_UNITS,
};
use registry_payment_simulator_connector::{Observation, ProviderCommand};
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
            || !self.simulation
            || !connection.binding.simulation
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
    ) -> Result<ProviderCommand, PaymentProblemCode> {
        let origin = url::Url::parse(&binding.provider.base_url)
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        let identity = serde_json::json!({
            "domain": "registry-adapter/payment-provider-command/v1",
            "provider": {
                "origin": origin.as_str(),
                "producer": binding.provider_credential_identity,
                "tenant": binding.provider.tenant,
                "biller": binding.provider.biller,
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
        let command = ProviderCommand {
            request_id: URL_SAFE_NO_PAD.encode(&digest[..9]),
            bill_id: URL_SAFE_NO_PAD.encode(&digest[9..16]),
            rtp_id: (u64::from_be_bytes(number) & ((1_u64 << 52) - 1)) + 1,
            payer_address: self.payer_financial_address.clone(),
            money: self.money.clone(),
        };
        command
            .validate()
            .map_err(|_| PaymentProblemCode::Unavailable)?;
        Ok(command)
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
    pub provider_command: ProviderCommand,
    pub bind_action: Option<PreparedRegistryAction>,
    pub bound: bool,
    pub first_send_at: Option<i64>,
    pub transfer_id: Option<String>,
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
        if self
            .binding
            .revision()
            .map_err(|_| PaymentProblemCode::Unavailable)?
            != self.binding_revision
            || self.bill.digest()? != self.bill_snapshot_digest
            || !self.bill.simulation
            || !self.binding.simulation
            || self.provider_command != self.bill.provider_command(&self.binding)?
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

pub fn digest(value: &impl Serialize) -> Result<String, PaymentProblemCode> {
    let value = serde_json::to_value(value).map_err(|_| PaymentProblemCode::Unavailable)?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| PaymentProblemCode::Unavailable)?;
    Ok(registry_platform_config::sha256_uri(&bytes))
}
