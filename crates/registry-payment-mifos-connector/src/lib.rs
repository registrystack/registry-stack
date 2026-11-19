// SPDX-License-Identifier: Apache-2.0
//! Bounded client for the released Mifos Payment Hub EE legacy contracts.
//!
//! Provider acceptance and provider-reported completion are observations, not
//! proof that a beneficiary was credited. Mutation calls are attempted once.

mod legacy_web_signature;

pub use legacy_web_signature::{
    legacy_batch_request_signature_digest, legacy_signature_digest, legacy_signature_preimage,
    LegacySignatureDigest, LegacySignatureError, LegacySignatureFuture, LegacySignatureHeaders,
    LegacySignaturePreimage, LegacyWebSignatureSigner, LegacyWebSignatureVerifier,
    LEGACY_WEB_SIGNATURE_PROFILE,
};

use registry_platform_httputil::client::{
    build_client, transport_protects_the_credential, BearerToken, OutboundOptions,
};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{borrow::Cow, time::Duration};
use url::Url;
use zeroize::Zeroizing;

pub const CONNECTOR_PROFILE: &str =
    "mifos-ph-ee-legacy/channel-v1.12.2+bulk-v1.12.1+operations-v1.17.1";
const RESPONSE_LIMIT: u64 = 65_536;
const MAX_TEXT: usize = 128;

/// Value-free failures. No provider body, header, credential, or caller value
/// is retained in the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    #[error("mifos connector configuration is invalid")]
    Configuration,
    #[error("mifos connector command is invalid")]
    Command,
    #[error("mifos provider authentication failed")]
    Authentication,
    #[error("mifos provider authorization failed")]
    Forbidden,
    #[error("mifos provider rejected the command")]
    Rejected,
    #[error("mifos provider response did not satisfy the pinned contract")]
    Protocol,
    #[error("mifos provider is unavailable")]
    Unavailable,
    #[error("mifos provider mutation outcome is unknown; do not submit a replacement")]
    OutcomeUnknown,
}

/// An exact positive decimal string and ISO-style uppercase currency code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactMoney {
    pub amount: String,
    pub currency: String,
}

impl ExactMoney {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if !valid_decimal(&self.amount)
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ConnectorError::Command);
        }
        Ok(())
    }
}

/// One provider party selector. PH-EE calls these key/value pairs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyIdentifier {
    pub key: String,
    pub value: String,
}

impl PartyIdentifier {
    fn validate(&self) -> Result<(), ConnectorError> {
        if !header_text(&self.key, 32) || !header_text(&self.value, MAX_TEXT) {
            return Err(ConnectorError::Command);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionType {
    pub scenario: String,
    pub sub_scenario: String,
    pub initiator: String,
    pub initiator_type: String,
}

impl TransactionType {
    fn validate(&self) -> Result<(), ConnectorError> {
        for value in [
            &self.scenario,
            &self.sub_scenario,
            &self.initiator,
            &self.initiator_type,
        ] {
            if !header_text(value, 32) {
                return Err(ConnectorError::Command);
            }
        }
        Ok(())
    }
}

/// Durable input for one P2G collection attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionCommand {
    pub correlation_id: String,
    pub payer: [PartyIdentifier; 2],
    pub money: ExactMoney,
    pub transaction_type: TransactionType,
}

impl CollectionCommand {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if !identifier(&self.correlation_id, MAX_TEXT) {
            return Err(ConnectorError::Command);
        }
        self.payer[0].validate()?;
        self.payer[1].validate()?;
        self.money.validate()?;
        self.transaction_type.validate()
    }

    /// Encode the channel v1.12.2 collection body.
    pub fn encode(&self) -> Result<Vec<u8>, ConnectorError> {
        build_collection_request(self)
    }

    pub fn decode_status(
        &self,
        accepted: &CollectionAccepted,
        bytes: &[u8],
    ) -> Result<CollectionObservation, ConnectorError> {
        parse_collection_status(self, accepted, bytes)
    }
}

/// Durable input for one G2P instruction submitted through the raw batch API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchCommand {
    /// Stable instruction correlation, sent as `X-CorrelationID`. The released
    /// raw item has no separate per-item request identifier.
    pub correlation_id: String,
    pub purpose: String,
    pub credit_party: Vec<PartyIdentifier>,
    pub debit_party: Vec<PartyIdentifier>,
    pub sub_type: String,
    pub money: ExactMoney,
    pub description_text: String,
    pub registering_institution_id: Option<String>,
    pub program_id: Option<String>,
    pub callback_url: Option<String>,
}

impl BatchCommand {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if !identifier(&self.correlation_id, MAX_TEXT)
            || !header_text(&self.purpose, MAX_TEXT)
            || self.credit_party.len() != 1
            || self.debit_party.len() != 1
            || !header_text(&self.sub_type, 32)
            || !bounded_text(&self.description_text, 256)
        {
            return Err(ConnectorError::Command);
        }
        for party in self.credit_party.iter().chain(&self.debit_party) {
            party.validate()?;
        }
        self.money.validate()?;
        for optional in [
            self.registering_institution_id.as_deref(),
            self.program_id.as_deref(),
        ] {
            if optional.is_some_and(|value| !header_text(value, MAX_TEXT)) {
                return Err(ConnectorError::Command);
            }
        }
        if let Some(callback) = &self.callback_url {
            validate_callback(callback)?;
        }
        Ok(())
    }

    /// Encode an array containing exactly one bulk v1.12.1 instruction.
    pub fn encode(&self) -> Result<Vec<u8>, ConnectorError> {
        build_batch_request(self)
    }

    /// Decode the operations v1.17.1 batch detail page for one instruction.
    /// `COMPLETED` becomes provider-confirmed, never settled or credited.
    pub fn decode_status(
        &self,
        accepted: &BatchAccepted,
        bytes: &[u8],
    ) -> Result<BatchObservation, ConnectorError> {
        parse_batch_status(self, accepted, bytes)
    }
}

/// Build the exact channel v1.12.2 request body for fixture replay or sending.
pub fn build_collection_request(command: &CollectionCommand) -> Result<Vec<u8>, ConnectorError> {
    command.validate()?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        payer: &'a [PartyIdentifier; 2],
        amount: Amount<'a>,
        transaction_type: &'a TransactionType,
        custom_data: [(); 0],
    }
    #[derive(Serialize)]
    struct Amount<'a> {
        amount: &'a str,
        currency: &'a str,
    }
    serde_json::to_vec(&Body {
        payer: &command.payer,
        amount: Amount {
            amount: &command.money.amount,
            currency: &command.money.currency,
        },
        transaction_type: &command.transaction_type,
        custom_data: [],
    })
    .map_err(|_| ConnectorError::Command)
}

/// Parse the exact channel acknowledgement without performing an HTTP call.
pub fn parse_collection_acceptance(bytes: &[u8]) -> Result<CollectionAccepted, ConnectorError> {
    check_body_bound(bytes)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Accepted {
        transaction_id: String,
    }
    let response: Accepted = serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
    let accepted = CollectionAccepted {
        transaction_id: response.transaction_id,
        state: SubmissionState::Accepted,
    };
    accepted.validate().map_err(|_| ConnectorError::Protocol)?;
    Ok(accepted)
}

/// Parse and correlate an operations transaction-request page without I/O.
pub fn parse_collection_status(
    command: &CollectionCommand,
    accepted: &CollectionAccepted,
    bytes: &[u8],
) -> Result<CollectionObservation, ConnectorError> {
    command.validate()?;
    accepted.validate()?;
    check_body_bound(bytes)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        content: Vec<Transaction>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Transaction {
        transaction_id: String,
        state: String,
        amount: Box<RawValue>,
        currency: String,
        client_correlation_id: String,
    }
    let mut page: Page = serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
    if page.content.is_empty() {
        return Ok(CollectionObservation {
            transaction_id: accepted.transaction_id.clone(),
            state: PaymentState::Unknown,
            money: command.money.clone(),
        });
    }
    if page.content.len() != 1 {
        return Err(ConnectorError::Protocol);
    }
    let transaction = page.content.remove(0);
    if transaction.transaction_id != accepted.transaction_id
        || transaction.client_correlation_id != command.correlation_id
        || transaction.currency != command.money.currency
        || !decimal_matches(&transaction.amount, &command.money.amount)
    {
        return Err(ConnectorError::Protocol);
    }
    let state = match transaction.state.as_str() {
        "INITIATED" | "IN_PROGRESS" | "RECEIVED" | "REQUEST_ACCEPTED" | "ACCEPTED" => {
            PaymentState::Pending
        }
        "SUCCESS" => PaymentState::ProviderConfirmed,
        "FAILED" | "REJECTED" => PaymentState::Failed,
        _ => PaymentState::Unknown,
    };
    Ok(CollectionObservation {
        transaction_id: transaction.transaction_id,
        state,
        money: command.money.clone(),
    })
}

/// Build the exact one-instruction bulk v1.12.1 request body.
pub fn build_batch_request(command: &BatchCommand) -> Result<Vec<u8>, ConnectorError> {
    command.validate()?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Instruction<'a> {
        credit_party: &'a [PartyIdentifier],
        debit_party: &'a [PartyIdentifier],
        sub_type: &'a str,
        amount: &'a str,
        currency: &'a str,
        description_text: &'a str,
    }
    serde_json::to_vec(&[Instruction {
        credit_party: &command.credit_party,
        debit_party: &command.debit_party,
        sub_type: &command.sub_type,
        amount: &command.money.amount,
        currency: &command.money.currency,
        description_text: &command.description_text,
    }])
    .map_err(|_| ConnectorError::Command)
}

/// Parse either released bulk acknowledgement form without performing I/O.
pub fn parse_batch_acceptance(
    command: &BatchCommand,
    http_status: u16,
    bytes: &[u8],
) -> Result<BatchAccepted, ConnectorError> {
    command.validate()?;
    if !matches!(http_status, 200 | 202) {
        return Err(ConnectorError::Protocol);
    }
    decode_batch_accepted(command, http_status, bytes)
}

/// Parse and correlate one operations batch-detail entry without I/O.
pub fn parse_batch_status(
    command: &BatchCommand,
    accepted: &BatchAccepted,
    bytes: &[u8],
) -> Result<BatchObservation, ConnectorError> {
    command.validate()?;
    accepted.validate()?;
    if accepted.request_id != command.correlation_id {
        return Err(ConnectorError::Protocol);
    }
    check_body_bound(bytes)?;
    #[derive(Deserialize)]
    struct Page {
        content: Vec<Transfer>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Transfer {
        transaction_id: String,
        status: String,
        payee_party_id: String,
        payee_party_id_type: String,
        payer_party_id: String,
        payer_party_id_type: String,
        amount: Box<RawValue>,
        currency: String,
        batch_id: String,
        client_correlation_id: String,
    }
    let mut page: Page = serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
    if page.content.is_empty() {
        return Ok(BatchObservation {
            batch_id: accepted.batch_id.clone(),
            instruction_correlation_id: command.correlation_id.clone(),
            provider_reference: None,
            state: PaymentState::Unknown,
            funding: command.debit_party[0].clone(),
            recipient: command.credit_party[0].clone(),
            money: command.money.clone(),
        });
    }
    if page.content.len() != 1 {
        return Err(ConnectorError::Protocol);
    }
    let transfer = page.content.remove(0);
    let recipient = &command.credit_party[0];
    let funding = &command.debit_party[0];
    if !identifier(&transfer.transaction_id, MAX_TEXT)
        || transfer.batch_id != accepted.batch_id
        || transfer.client_correlation_id != command.correlation_id
        || transfer.payee_party_id != recipient.value
        || transfer.payee_party_id_type != recipient.key
        || transfer.payer_party_id != funding.value
        || transfer.payer_party_id_type != funding.key
        || transfer.currency != command.money.currency
        || !decimal_matches(&transfer.amount, &command.money.amount)
    {
        return Err(ConnectorError::Protocol);
    }
    let state = match transfer.status.as_str() {
        "IN_PROGRESS" => PaymentState::Pending,
        "COMPLETED" => PaymentState::ProviderConfirmed,
        "FAILED" | "EXCEPTION" => PaymentState::Failed,
        "UNKNOWN" => PaymentState::Unknown,
        _ => PaymentState::Unknown,
    };
    Ok(BatchObservation {
        batch_id: accepted.batch_id.clone(),
        instruction_correlation_id: command.correlation_id.clone(),
        provider_reference: Some(transfer.transaction_id),
        state,
        funding: funding.clone(),
        recipient: recipient.clone(),
        money: command.money.clone(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubmissionState {
    Accepted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PaymentState {
    Pending,
    /// The pinned operations API reports its terminal success state. This is
    /// not proof of beneficiary credit or inter-provider settlement.
    ProviderConfirmed,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionAccepted {
    pub transaction_id: String,
    pub state: SubmissionState,
}

impl CollectionAccepted {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.state != SubmissionState::Accepted || !identifier(&self.transaction_id, MAX_TEXT) {
            return Err(ConnectorError::Command);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchAccepted {
    pub batch_id: String,
    pub request_id: String,
    pub state: SubmissionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_poll_after_seconds: Option<u64>,
}

impl BatchAccepted {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.state != SubmissionState::Accepted
            || !identifier(&self.batch_id, MAX_TEXT)
            || !identifier(&self.request_id, MAX_TEXT)
            || self
                .suggested_poll_after_seconds
                .is_some_and(|value| value > 86_400)
        {
            return Err(ConnectorError::Command);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionObservation {
    pub transaction_id: String,
    pub state: PaymentState,
    pub money: ExactMoney,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchObservation {
    pub batch_id: String,
    pub instruction_correlation_id: String,
    pub provider_reference: Option<String>,
    pub state: PaymentState,
    pub funding: PartyIdentifier,
    pub recipient: PartyIdentifier,
    pub money: ExactMoney,
}

/// Deployment-owned endpoints and non-secret routing headers. Each component
/// has its own URL because released PH-EE is not a monolith.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MifosConnection {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub channel_base_url: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub bulk_base_url: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub operations_base_url: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 128), pattern(r"^[\x20-\x7e]+$"))
    )]
    pub tenant: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 32), pattern(r"^[\x20-\x7e]+$"))
    )]
    pub payment_scheme: String,
}

impl MifosConnection {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        for base in [
            &self.channel_base_url,
            &self.bulk_base_url,
            &self.operations_base_url,
        ] {
            parse_base(base)?;
        }
        if !header_text(&self.tenant, 128) || !header_text(&self.payment_scheme, 32) {
            return Err(ConnectorError::Configuration);
        }
        Ok(())
    }
}

/// A precomputed PH-EE `X-SIGNATURE` value. Signature construction and key
/// custody remain with the operator's JWS implementation.
pub struct SecretHeader(Zeroizing<String>);

impl SecretHeader {
    pub fn new(value: impl Into<String>) -> Result<Self, ConnectorError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 16 * 1024
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ConnectorError::Configuration);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_bytes(self.0.as_bytes())
            .expect("SecretHeader construction guarantees a valid header value");
        value.set_sensitive(true);
        value
    }

    /// Borrow the validated ASCII signature bytes for a host-side verifier.
    ///
    /// The value is authentication material. Callers must not log it or place
    /// it in diagnostics, metrics, persisted attempts, or public problems.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Credentials supplied only at one send boundary. The connector does not
/// persist or refresh them and accepts no arbitrary caller-authored headers.
#[derive(Clone, Copy, Default)]
pub struct RequestAuth<'a> {
    bearer: Option<&'a BearerToken>,
    signature: Option<&'a SecretHeader>,
}

impl<'a> RequestAuth<'a> {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            bearer: None,
            signature: None,
        }
    }

    #[must_use]
    pub const fn bearer(token: &'a BearerToken) -> Self {
        Self {
            bearer: Some(token),
            signature: None,
        }
    }

    #[must_use]
    pub const fn signature(signature: &'a SecretHeader) -> Self {
        Self {
            bearer: None,
            signature: Some(signature),
        }
    }

    #[must_use]
    pub const fn bearer_and_signature(token: &'a BearerToken, signature: &'a SecretHeader) -> Self {
        Self {
            bearer: Some(token),
            signature: Some(signature),
        }
    }
}

/// One-attempt HTTP client. It never retries a mutation, including connection
/// errors, timeouts, oversized responses, or malformed acknowledgements.
pub struct MifosClient {
    connection: MifosConnection,
    channel: Url,
    bulk: Url,
    operations: Url,
    http: reqwest::Client,
}

impl MifosClient {
    pub fn new(connection: MifosConnection) -> Result<Self, ConnectorError> {
        connection.validate()?;
        let channel = parse_base(&connection.channel_base_url)?;
        let bulk = parse_base(&connection.bulk_base_url)?;
        let operations = parse_base(&connection.operations_base_url)?;
        let http = build_client(OutboundOptions {
            request_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(5),
            user_agent: Some(CONNECTOR_PROFILE),
            trusted_root_certificates: None,
        })
        .map_err(|_| ConnectorError::Configuration)?;
        Ok(Self {
            connection,
            channel,
            bulk,
            operations,
            http,
        })
    }

    pub async fn submit_collection(
        &self,
        command: &CollectionCommand,
        auth: &RequestAuth<'_>,
    ) -> Result<CollectionAccepted, ConnectorError> {
        let body = command.encode()?;
        let request = self
            .http
            .post(endpoint(&self.channel, "channel/collection")?)
            .header("Platform-TenantId", &self.connection.tenant)
            .header("X-CorrelationID", &command.correlation_id)
            .header("X-Payment-Scheme", &self.connection.payment_scheme)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let response = apply_auth(request, auth)
            .send()
            .await
            .map_err(|_| ConnectorError::OutcomeUnknown)?;
        let bytes = mutation_response(response, &[200]).await?;
        parse_collection_acceptance(&bytes).map_err(|_| ConnectorError::OutcomeUnknown)
    }

    pub async fn collection_status(
        &self,
        command: &CollectionCommand,
        accepted: &CollectionAccepted,
        auth: &RequestAuth<'_>,
    ) -> Result<CollectionObservation, ConnectorError> {
        command.validate()?;
        accepted.validate()?;
        let mut url = endpoint(&self.operations, "api/v1/transactionRequests")?;
        url.query_pairs_mut()
            .append_pair("page", "0")
            .append_pair("size", "2")
            .append_pair("clientCorrelationId", &command.correlation_id);
        let request = self
            .http
            .get(url)
            .header("Platform-TenantId", &self.connection.tenant);
        let Some(bytes) = observation_response(apply_auth(request, auth).send().await).await?
        else {
            return Ok(CollectionObservation {
                transaction_id: accepted.transaction_id.clone(),
                state: PaymentState::Unknown,
                money: command.money.clone(),
            });
        };
        command.decode_status(accepted, &bytes)
    }

    pub async fn submit_batch(
        &self,
        command: &BatchCommand,
        auth: &RequestAuth<'_>,
    ) -> Result<BatchAccepted, ConnectorError> {
        let body = command.encode()?;
        let mut request = self
            .http
            .post(endpoint(&self.bulk, "batchtransactions")?)
            .header("Platform-TenantId", &self.connection.tenant)
            .header("X-CorrelationID", &command.correlation_id)
            .header("Purpose", &command.purpose)
            .header("Type", "raw")
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(value) = &command.registering_institution_id {
            request = request.header("X-Registering-Institution-ID", value);
        }
        if let Some(value) = &command.program_id {
            request = request.header("X-Program-ID", value);
        }
        if let Some(value) = &command.callback_url {
            request = request.header("X-CallbackURL", value);
        }
        let response = apply_auth(request, auth)
            .send()
            .await
            .map_err(|_| ConnectorError::OutcomeUnknown)?;
        let status = response.status().as_u16();
        let bytes = mutation_response(response, &[200, 202]).await?;
        parse_batch_acceptance(command, status, &bytes).map_err(|_| ConnectorError::OutcomeUnknown)
    }

    pub async fn batch_status(
        &self,
        command: &BatchCommand,
        accepted: &BatchAccepted,
        auth: &RequestAuth<'_>,
    ) -> Result<BatchObservation, ConnectorError> {
        command.validate()?;
        accepted.validate()?;
        let mut url = endpoint(&self.operations, "api/v1/batch/detail")?;
        url.query_pairs_mut()
            .append_pair("batchId", &accepted.batch_id)
            .append_pair("status", "ALL")
            .append_pair("pageNo", "0")
            .append_pair("pageSize", "2")
            .append_pair("command", "json");
        let request = self
            .http
            .get(url)
            .header("Platform-TenantId", &self.connection.tenant);
        let Some(bytes) = observation_response(apply_auth(request, auth).send().await).await?
        else {
            return Ok(BatchObservation {
                batch_id: accepted.batch_id.clone(),
                instruction_correlation_id: command.correlation_id.clone(),
                provider_reference: None,
                state: PaymentState::Unknown,
                funding: command.debit_party[0].clone(),
                recipient: command.credit_party[0].clone(),
                money: command.money.clone(),
            });
        };
        command.decode_status(accepted, &bytes)
    }
}

fn decode_batch_accepted(
    command: &BatchCommand,
    status: u16,
    bytes: &[u8],
) -> Result<BatchAccepted, ConnectorError> {
    check_body_bound(bytes)?;
    let accepted = if status == 200 {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Queued {
            batch_id: String,
            request_id: String,
            status: String,
        }
        let response: Queued =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
        if response.status != "queued" || response.request_id != command.correlation_id {
            return Err(ConnectorError::Protocol);
        }
        BatchAccepted {
            batch_id: response.batch_id,
            request_id: response.request_id,
            state: SubmissionState::Accepted,
            suggested_poll_after_seconds: None,
        }
    } else {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase", deny_unknown_fields)]
        struct Polling {
            polling_path: String,
            suggested_callback_seconds: StringOrNumber,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrNumber {
            String(String),
            Number(u64),
        }
        let response: Polling =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
        let prefix = "/batch/Summary/";
        let batch_id = response
            .polling_path
            .strip_prefix(prefix)
            .ok_or(ConnectorError::Protocol)?
            .to_owned();
        let seconds = match response.suggested_callback_seconds {
            StringOrNumber::String(value) => {
                value.parse::<u64>().map_err(|_| ConnectorError::Protocol)?
            }
            StringOrNumber::Number(value) => value,
        };
        BatchAccepted {
            batch_id,
            request_id: command.correlation_id.clone(),
            state: SubmissionState::Accepted,
            suggested_poll_after_seconds: Some(seconds),
        }
    };
    accepted.validate().map_err(|_| ConnectorError::Protocol)?;
    Ok(accepted)
}

fn apply_auth(
    mut request: reqwest::RequestBuilder,
    auth: &RequestAuth<'_>,
) -> reqwest::RequestBuilder {
    if let Some(token) = auth.bearer {
        request = request.header(AUTHORIZATION, token.authorization_header_value());
    }
    if let Some(signature) = auth.signature {
        request = request.header("X-SIGNATURE", signature.header_value());
    }
    request
}

async fn mutation_response(
    response: reqwest::Response,
    expected: &[u16],
) -> Result<Vec<u8>, ConnectorError> {
    match response.status().as_u16() {
        401 => return Err(ConnectorError::Authentication),
        403 => return Err(ConnectorError::Forbidden),
        status if (400..500).contains(&status) => return Err(ConnectorError::Rejected),
        status if !expected.contains(&status) => return Err(ConnectorError::OutcomeUnknown),
        _ => {}
    }
    if !json_content_type(&response) {
        return Err(ConnectorError::OutcomeUnknown);
    }
    registry_platform_httputil::read_bounded(response, RESPONSE_LIMIT)
        .await
        .map_err(|_| ConnectorError::OutcomeUnknown)
}

async fn observation_response(
    response: Result<reqwest::Response, reqwest::Error>,
) -> Result<Option<Vec<u8>>, ConnectorError> {
    let response = response.map_err(|_| ConnectorError::Unavailable)?;
    match response.status().as_u16() {
        200 => {}
        401 => return Err(ConnectorError::Authentication),
        403 => return Err(ConnectorError::Forbidden),
        404 => return Ok(None),
        _ => return Err(ConnectorError::Unavailable),
    }
    if !json_content_type(&response) {
        return Err(ConnectorError::Protocol);
    }
    registry_platform_httputil::read_bounded(response, RESPONSE_LIMIT)
        .await
        .map(Some)
        .map_err(|_| ConnectorError::Unavailable)
}

fn json_content_type(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        == Some("application/json")
}

fn endpoint(base: &Url, path: &str) -> Result<Url, ConnectorError> {
    base.join(path).map_err(|_| ConnectorError::Configuration)
}

fn parse_base(value: &str) -> Result<Url, ConnectorError> {
    let url = Url::parse(value).map_err(|_| ConnectorError::Configuration)?;
    if !transport_protects_the_credential(&url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(ConnectorError::Configuration);
    }
    Ok(url)
}

fn validate_callback(value: &str) -> Result<(), ConnectorError> {
    let url = Url::parse(value).map_err(|_| ConnectorError::Command)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ConnectorError::Command);
    }
    Ok(())
}

fn check_body_bound(bytes: &[u8]) -> Result<(), ConnectorError> {
    if bytes.len() > RESPONSE_LIMIT as usize {
        return Err(ConnectorError::Protocol);
    }
    Ok(())
}

fn decimal_matches(raw: &RawValue, expected: &str) -> bool {
    let value: Cow<'_, str> = if raw.get().starts_with('"') {
        match serde_json::from_str::<String>(raw.get()) {
            Ok(value) => Cow::Owned(value),
            Err(_) => return false,
        }
    } else {
        Cow::Borrowed(raw.get())
    };
    normalize_decimal(&value) == normalize_decimal(expected)
}

fn normalize_decimal(value: &str) -> Option<(&str, &str)> {
    if !valid_decimal(value) {
        return None;
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    Some((whole, fraction))
}

fn valid_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 || value.starts_with('-') || value.starts_with('+') {
        return false;
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || fraction.is_some_and(|part| {
            part.is_empty() || part.len() > 18 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    whole.bytes().any(|byte| byte != b'0')
        || fraction.is_some_and(|part| part.bytes().any(|byte| byte != b'0'))
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn header_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
