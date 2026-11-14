// SPDX-License-Identifier: Apache-2.0
//! Runtime-free payment collection wire contract. Financial authority stays
//! with the configured provider and receipt authority with the owning registry.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum exact integer shared with JSON consumers and the synthetic provider.
pub const MAX_MINOR_UNITS: u64 = 9_007_199_254_740_991;

/// Closed problem codes shared by the payment host and native clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PaymentProblemCode {
    #[serde(rename = "adapter.payment.authentication-required")]
    Unauthenticated,
    #[serde(rename = "adapter.payment.forbidden")]
    Forbidden,
    #[serde(rename = "adapter.payment.invalid-request")]
    InvalidRequest,
    #[serde(rename = "adapter.payment.conflict")]
    Conflict,
    #[serde(rename = "adapter.payment.not-found")]
    NotFound,
    #[serde(rename = "adapter.payment.receipt-unresolved")]
    ReceiptUnresolved,
    #[serde(rename = "adapter.payment.receipt-expired")]
    ReceiptExpired,
    #[serde(rename = "adapter.payment.recovery-held")]
    RecoveryHeld,
    #[serde(rename = "adapter.payment.outcome-unknown")]
    OutcomeUnknown,
    #[serde(rename = "adapter.payment.unavailable")]
    Unavailable,
    #[serde(rename = "adapter.payment.provider-protocol")]
    ProviderProtocol,
}

impl PaymentProblemCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "adapter.payment.authentication-required",
            Self::Forbidden => "adapter.payment.forbidden",
            Self::InvalidRequest => "adapter.payment.invalid-request",
            Self::Conflict => "adapter.payment.conflict",
            Self::NotFound => "adapter.payment.not-found",
            Self::ReceiptUnresolved => "adapter.payment.receipt-unresolved",
            Self::ReceiptExpired => "adapter.payment.receipt-expired",
            Self::RecoveryHeld => "adapter.payment.recovery-held",
            Self::OutcomeUnknown => "adapter.payment.outcome-unknown",
            Self::Unavailable => "adapter.payment.unavailable",
            Self::ProviderProtocol => "adapter.payment.provider-protocol",
        }
    }

    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::InvalidRequest => 422,
            Self::Conflict | Self::RecoveryHeld => 409,
            Self::NotFound | Self::ReceiptUnresolved => 404,
            Self::ReceiptExpired => 410,
            Self::ProviderProtocol => 502,
            Self::OutcomeUnknown | Self::Unavailable => 503,
        }
    }

    #[must_use]
    pub fn type_uri(self) -> String {
        format!("urn:registry:problem:{}", self.as_str())
    }
}

/// Value-free problem details. Recovery outcomes are named even when the
/// transport completed: no uncertain result grants a new payment attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentProblem {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub code: PaymentProblemCode,
}

impl From<PaymentProblemCode> for PaymentProblem {
    fn from(code: PaymentProblemCode) -> Self {
        Self {
            type_uri: code.type_uri(),
            title: code.as_str().to_owned(),
            status: code.status(),
            code,
        }
    }
}

/// A refused wire value. Messages never contain caller or provider values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("payment contract: {0}")]
pub struct ContractError(&'static str);

/// An exact positive decimal amount. Scale belongs to the configured currency
/// policy; wire amounts are strings so no binary floating-point rounding occurs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Money {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 24), pattern(r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$"), extend("not" = serde_json::json!({"pattern": r"^0(\.0{1,6})?$"}))))]
    pub value: String,
    #[cfg_attr(feature = "schema", schemars(pattern("^[A-Z]{3}$")))]
    pub currency: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 0, max = 6)))]
    pub scale: u8,
}

impl Money {
    /// Parse bounded decimal text into exact minor units.
    ///
    /// # Errors
    /// Refuses noncanonical decimal syntax, excess precision, unsupported
    /// currency/scale, zero, and amounts outside the portable integer range.
    pub fn minor_units(&self) -> Result<u64, ContractError> {
        if self.scale > 6
            || self.currency.len() != 3
            || !self.currency.bytes().all(|b| b.is_ascii_uppercase())
            || self.value.len() > 24
        {
            return Err(ContractError("invalid currency or precision"));
        }
        let (whole, fraction) = match self.value.split_once('.') {
            Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
            Some(_) => return Err(ContractError("invalid decimal")),
            None => (self.value.as_str(), ""),
        };
        if whole.is_empty()
            || (whole.len() > 1 && whole.starts_with('0'))
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
            || fraction.len() > usize::from(self.scale)
        {
            return Err(ContractError("invalid decimal"));
        }
        let factor = 10_u64.pow(u32::from(self.scale));
        let whole = whole
            .parse::<u64>()
            .map_err(|_| ContractError("amount overflow"))?;
        let fractional = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<u64>()
                .map_err(|_| ContractError("invalid decimal"))?
                * 10_u64.pow(
                    u32::from(self.scale)
                        - u32::try_from(fraction.len())
                            .map_err(|_| ContractError("invalid decimal"))?,
                )
        };
        let amount = whole
            .checked_mul(factor)
            .and_then(|v| v.checked_add(fractional))
            .filter(|v| *v > 0 && *v <= MAX_MINOR_UNITS)
            .ok_or(ContractError("amount outside positive portable range"))?;
        Ok(amount)
    }

    /// Canonical decimal representation with the currency's configured scale.
    ///
    /// # Errors
    /// Uses the same bounds as [`Self::minor_units`].
    pub fn canonical(&self) -> Result<Self, ContractError> {
        let minor = self.minor_units()?;
        let factor = 10_u64.pow(u32::from(self.scale));
        let value = if self.scale == 0 {
            minor.to_string()
        } else {
            format!(
                "{}.{:0width$}",
                minor / factor,
                minor % factor,
                width = usize::from(self.scale)
            )
        };
        Ok(Self {
            value,
            currency: self.currency.clone(),
            scale: self.scale,
        })
    }
}

/// Caller intent names a bill, never financial facts or provider routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestCollection {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub bill_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub bill_version: u64,
}

/// A disbursement intent names an approved, immutable instruction held by the
/// owning registry. The caller cannot supply amount, destination or funding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestDisbursement {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_record_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub instruction_version: u64,
}

/// Read one saved disbursement and its current provider observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadDisbursement {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub disbursement_id: Uuid,
}

impl RequestDisbursement {
    /// # Errors
    /// Refuses a nil identifier or a nonportable/nonpositive version.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bill(self.instruction_record_id, self.instruction_version)
    }
}

/// A provider accepted the exact instruction command for asynchronous work.
/// This is not confirmation that the recipient was paid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisbursementAccepted {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub disbursement_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_record_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub instruction_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
}

impl DisbursementAccepted {
    /// # Errors
    /// Refuses a missing or malformed durable identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bill(self.instruction_record_id, self.instruction_version)?;
        if self.instruction_id.is_nil() {
            return Err(ContractError("invalid instruction identity"));
        }
        if self.disbursement_id.is_nil() || !bounded_text(&self.binding_revision, 128) {
            return Err(ContractError("invalid disbursement binding"));
        }
        Ok(())
    }
}

/// Only provider-confirmed means the pinned provider reported completion.
/// It does not by itself claim end-recipient credit or settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum DisbursementState {
    Accepted,
    Pending,
    ProviderConfirmed,
    Failed,
    Unknown,
}

/// A bounded observation of one saved disbursement instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisbursementStatus {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub disbursement_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_record_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub instruction_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
    pub state: DisbursementState,
    pub money: Money,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl DisbursementStatus {
    /// # Errors
    /// Refuses a status that carries contradictory provider evidence.
    pub fn validate(&self) -> Result<(), ContractError> {
        DisbursementAccepted {
            disbursement_id: self.disbursement_id,
            instruction_record_id: self.instruction_record_id,
            instruction_id: self.instruction_id,
            instruction_version: self.instruction_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.simulation,
        }
        .validate()?;
        self.money.minor_units()?;
        if (self.state == DisbursementState::ProviderConfirmed)
            != self
                .provider_reference
                .as_ref()
                .is_some_and(|value| bounded_text(value, 128))
            || (self.state != DisbursementState::ProviderConfirmed
                && self.provider_reference.is_some())
            || (self.state == DisbursementState::Failed)
                != self
                    .failure_reason
                    .as_ref()
                    .is_some_and(|value| bounded_text(value, 128))
            || (self.state != DisbursementState::Failed && self.failure_reason.is_some())
        {
            return Err(ContractError("state and evidence disagree"));
        }
        Ok(())
    }
}

/// Ask the Adapter to report a previously verified provider completion to
/// the instruction registry. The caller supplies no status or evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordProviderConfirmation {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub disbursement_id: Uuid,
}

/// The exact provider completion reported to the authoritative instruction.
/// This does not claim beneficiary credit or final settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderConfirmation {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub disbursement_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_record_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub instruction_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub instruction_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
    pub money: Money,
    pub provider_reference: String,
    pub provider_result_digest: String,
}

impl ProviderConfirmation {
    /// # Errors
    /// Refuses a confirmation without exact binding and provider evidence.
    pub fn validate(&self) -> Result<(), ContractError> {
        DisbursementStatus {
            disbursement_id: self.disbursement_id,
            instruction_record_id: self.instruction_record_id,
            instruction_id: self.instruction_id,
            instruction_version: self.instruction_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.simulation,
            state: DisbursementState::ProviderConfirmed,
            money: self.money.clone(),
            provider_reference: Some(self.provider_reference.clone()),
            failure_reason: None,
        }
        .validate()?;
        if self.provider_result_digest.len() != 64
            || !self
                .provider_result_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError("invalid provider result digest"));
        }
        Ok(())
    }
}

impl RequestCollection {
    /// # Errors
    /// Refuses a nil identifier or a nonportable/nonpositive bill version.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bill(self.bill_id, self.bill_version)
    }
}

/// Input for an authoritative provider observation through the bound module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadCollection {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub collection_id: Uuid,
}

/// Input for the restricted receipt operation. An identifier is a lookup key,
/// not receipt evidence and not authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordReceipt {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub collection_id: Uuid,
}

/// Returned only after the provider's durable acceptance is established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionAccepted {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub bill_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub bill_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
}

impl CollectionAccepted {
    /// # Errors
    /// Refuses missing or malformed durable identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bill(self.bill_id, self.bill_version)?;
        if self.collection_id.is_nil() || !bounded_text(&self.binding_revision, 128) {
            return Err(ContractError("invalid collection binding"));
        }
        Ok(())
    }
}

/// Provider state. Unknown is unresolved and never authorizes a replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum CollectionState {
    Accepted,
    Pending,
    Confirmed,
    Failed,
    Unknown,
}

/// Verified observation, retaining the attempt's original binding and provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionStatus {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub bill_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub bill_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
    pub state: CollectionState,
    pub money: Money,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl CollectionStatus {
    #[must_use]
    pub fn acceptance(&self) -> CollectionAccepted {
        CollectionAccepted {
            collection_id: self.collection_id,
            bill_id: self.bill_id,
            bill_version: self.bill_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.simulation,
        }
    }

    /// # Errors
    /// Refuses inconsistent evidence/state, malformed identity or money.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.acceptance().validate()?;
        self.money.minor_units()?;
        if (self.state == CollectionState::Confirmed)
            != self
                .provider_reference
                .as_ref()
                .is_some_and(|s| bounded_text(s, 128))
            || (self.state != CollectionState::Confirmed && self.provider_reference.is_some())
            || (self.state == CollectionState::Failed)
                != self
                    .failure_reason
                    .as_ref()
                    .is_some_and(|s| bounded_text(s, 128))
            || (self.state != CollectionState::Failed && self.failure_reason.is_some())
        {
            return Err(ContractError("state and evidence disagree"));
        }
        Ok(())
    }
}

/// Exact receipt recorded by the service-owned registry Action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryReceipt {
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "schema", schemars(schema_with = "non_nil_uuid_schema"))]
    pub bill_id: Uuid,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = 9_007_199_254_740_991_u64))
    )]
    pub bill_version: u64,
    pub binding_revision: String,
    pub simulation: bool,
    pub money: Money,
    pub provider_reference: String,
    pub receipt_id: String,
}

impl RegistryReceipt {
    /// # Errors
    /// Refuses a receipt without exact binding, amount or reference.
    pub fn validate(&self) -> Result<(), ContractError> {
        let status = CollectionStatus {
            collection_id: self.collection_id,
            bill_id: self.bill_id,
            bill_version: self.bill_version,
            binding_revision: self.binding_revision.clone(),
            simulation: self.simulation,
            state: CollectionState::Confirmed,
            money: self.money.clone(),
            provider_reference: Some(self.provider_reference.clone()),
            failure_reason: None,
        };
        status.validate()?;
        if !bounded_text(&self.receipt_id, 128) {
            return Err(ContractError("invalid receipt identity"));
        }
        Ok(())
    }
}

fn validate_bill(id: Uuid, version: u64) -> Result<(), ContractError> {
    if id.is_nil() || version == 0 || version > MAX_MINOR_UNITS {
        return Err(ContractError("invalid bill identity"));
    }
    Ok(())
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(feature = "schema")]
fn non_nil_uuid_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
