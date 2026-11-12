// SPDX-License-Identifier: Apache-2.0
//! The explicitly synthetic, local-only P2G profile. No live payment support.

use registry_payment_protocol::{CollectionState, Money, MAX_MINOR_UNITS};
use registry_platform_httputil::client::{build_client, BearerToken, OutboundOptions};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::time::Duration;
use url::{Host, Url};

pub const CONNECTOR_VERSION: &str = "simulator-p2g/v1";
const RESPONSE_LIMIT: u64 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    #[error("adapter.payment.provider-configuration")]
    Configuration,
    #[error("adapter.payment.provider-command")]
    Command,
    #[error("adapter.payment.provider-protocol")]
    Protocol,
    #[error("adapter.payment.provider-unavailable")]
    Unavailable,
    #[error("adapter.payment.provider-outcome-unknown")]
    Unknown,
}

/// Operator-owned synthetic provider routing. Credentials are supplied only at
/// the send boundary and never belong to a persisted command or connection.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulatorConnection {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 20), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub tenant: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 20), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub biller: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 10), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub biller_name: String,
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::Url", length(min = 1, max = 100))
    )]
    pub callback_url: String,
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 10), pattern(r"^[\x21-\x7e]+$"))
    )]
    pub payer_fi_bic: String,
}

impl SimulatorConnection {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        registry_platform_yaml::Url::new(self.base_url.clone())
            .map_err(|_| ConnectorError::Configuration)?;
        registry_platform_yaml::Url::new(self.callback_url.clone())
            .map_err(|_| ConnectorError::Configuration)?;
        let url = Url::parse(&self.base_url).map_err(|_| ConnectorError::Configuration)?;
        let loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if !loopback
            || url.scheme() != "http"
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !text(&self.tenant, 20)
            || !text(&self.biller, 20)
            || !text(&self.biller_name, 10)
            || !text(&self.payer_fi_bic, 10)
            || !text(&self.callback_url, 100)
        {
            return Err(ConnectorError::Configuration);
        }
        let callback = Url::parse(&self.callback_url).map_err(|_| ConnectorError::Configuration)?;
        if callback.scheme() != "https"
            || !callback.username().is_empty()
            || callback.password().is_some()
            || callback.query().is_some()
            || callback.fragment().is_some()
        {
            return Err(ConnectorError::Configuration);
        }
        Ok(())
    }
}

/// Persisted identity and exact financial facts for one provider command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCommand {
    pub request_id: String,
    pub rtp_id: u64,
    pub bill_id: String,
    pub payer_address: String,
    pub money: Money,
}

impl ProviderCommand {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if !identifier(&self.request_id, 12)
            || !identifier(&self.bill_id, 10)
            || self.rtp_id == 0
            || self.rtp_id > MAX_MINOR_UNITS
            || !text(&self.payer_address, 30)
        {
            return Err(ConnectorError::Command);
        }
        self.money
            .minor_units()
            .map_err(|_| ConnectorError::Command)?;
        Ok(())
    }

    pub fn encode(&self, connection: &SimulatorConnection) -> Result<Vec<u8>, ConnectorError> {
        self.validate()?;
        connection.validate()?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            request_id: &'a str,
            rtp_id: u64,
            #[serde(rename = "billID")]
            bill_id: &'a str,
            request_type: &'static str,
            payer_fi_details: Payer<'a>,
            bill_details: Bill<'a>,
        }
        #[derive(Serialize)]
        struct Payer<'a> {
            #[serde(rename = "payerFIBIC")]
            bic: &'a str,
            #[serde(rename = "financialAddress")]
            address: &'a str,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Bill<'a> {
            biller_name: &'a str,
            amount: Box<RawValue>,
            currency: &'a str,
        }
        let money = self
            .money
            .canonical()
            .map_err(|_| ConnectorError::Command)?;
        let amount = RawValue::from_string(money.value).map_err(|_| ConnectorError::Command)?;
        serde_json::to_vec(&Request {
            request_id: &self.request_id,
            rtp_id: self.rtp_id,
            bill_id: &self.bill_id,
            request_type: "00",
            payer_fi_details: Payer {
                bic: &connection.payer_fi_bic,
                address: &self.payer_address,
            },
            bill_details: Bill {
                biller_name: &connection.biller_name,
                amount,
                currency: &self.money.currency,
            },
        })
        .map_err(|_| ConnectorError::Command)
    }

    pub fn decode_accepted(&self, bytes: &[u8]) -> Result<String, ConnectorError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Accepted {
            response_code: String,
            response_description: String,
            #[serde(rename = "requestID")]
            request_id: String,
            rtp_id: u64,
            transfer_request_id: String,
        }
        if bytes.len() > RESPONSE_LIMIT as usize {
            return Err(ConnectorError::Protocol);
        }
        let response: Accepted =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
        if response.response_code != "00"
            || response.response_description.len() > 200
            || response.request_id != self.request_id
            || response.rtp_id != self.rtp_id
            || !identifier(&response.transfer_request_id, 50)
        {
            return Err(ConnectorError::Protocol);
        }
        Ok(response.transfer_request_id)
    }

    pub fn decode_status(
        &self,
        transfer: &str,
        bytes: &[u8],
    ) -> Result<Observation, ConnectorError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Status {
            transfer_request_id: String,
            #[serde(rename = "RequestId")]
            request_id: String,
            rtp_id: u64,
            bill_id: String,
            amount: Box<RawValue>,
            currency: String,
            request_status: String,
            payment_status: String,
            last_update_date: u64,
            #[serde(rename = "PaymentReferenceID", default)]
            reference: Option<String>,
            #[serde(default)]
            failure_reason: Option<String>,
        }
        self.validate()?;
        if bytes.len() > RESPONSE_LIMIT as usize {
            return Err(ConnectorError::Protocol);
        }
        let response: Status =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::Protocol)?;
        let amount = Money {
            value: response.amount.get().to_owned(),
            currency: response.currency,
            scale: self.money.scale,
        };
        if response.transfer_request_id != transfer
            || response.request_id != self.request_id
            || response.rtp_id != self.rtp_id
            || response.bill_id != self.bill_id
            || amount.currency != self.money.currency
            || amount.minor_units().map_err(|_| ConnectorError::Protocol)?
                != self
                    .money
                    .minor_units()
                    .map_err(|_| ConnectorError::Command)?
        {
            return Err(ConnectorError::Protocol);
        }
        let state = match (
            response.request_status.as_str(),
            response.payment_status.as_str(),
        ) {
            ("PND" | "COM", "PENDING")
                if response.reference.is_none() && response.failure_reason.is_none() =>
            {
                CollectionState::Pending
            }
            ("COM", "PAID")
                if response.failure_reason.is_none()
                    && response
                        .reference
                        .as_ref()
                        .is_some_and(|s| s.starts_with("SIM-") && identifier(s, 20)) =>
            {
                CollectionState::Confirmed
            }
            ("RJC", "FAILED")
                if response.reference.is_none()
                    && response.failure_reason.as_deref() == Some("payer-rejected") =>
            {
                CollectionState::Failed
            }
            ("EXP", "EXPIRED")
                if response.reference.is_none()
                    && response.failure_reason.as_deref() == Some("request-expired") =>
            {
                CollectionState::Failed
            }
            _ => return Err(ConnectorError::Protocol),
        };
        Ok(Observation {
            state,
            provider_reference: response.reference,
            failure_reason: response.failure_reason,
            observed_at: response.last_update_date,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub state: CollectionState,
    pub provider_reference: Option<String>,
    pub failure_reason: Option<String>,
    pub observed_at: u64,
}

/// One bounded HTTP exchange per call. Retries belong to the durable host and
/// its saved command/window, never to this transport.
pub struct SimulatorClient {
    connection: SimulatorConnection,
    base_url: Url,
    http: reqwest::Client,
}

impl SimulatorClient {
    pub fn new(connection: SimulatorConnection) -> Result<Self, ConnectorError> {
        connection.validate()?;
        let base_url =
            Url::parse(&connection.base_url).map_err(|_| ConnectorError::Configuration)?;
        let http = build_client(OutboundOptions {
            request_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(5),
            user_agent: None,
            trusted_root_certificates: None,
        })
        .map_err(|_| ConnectorError::Configuration)?;
        Ok(Self {
            connection,
            base_url,
            http,
        })
    }

    pub async fn submit(
        &self,
        command: &ProviderCommand,
        token: &BearerToken,
    ) -> Result<String, ConnectorError> {
        let body = command.encode(&self.connection)?;
        let response = self
            .http
            .post(
                self.base_url
                    .join("rtpRequest")
                    .map_err(|_| ConnectorError::Configuration)?,
            )
            .header("Authorization", token.authorization_header_value())
            .header("X-Platform-TenantId", &self.connection.tenant)
            .header("X-billerId", &self.connection.biller)
            .header("X-CorrelationID", &command.request_id)
            .header("X-Callback-URL", &self.connection.callback_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| ConnectorError::Unknown)?;
        let bytes = checked_response(response, None)
            .await
            .map_err(|_| ConnectorError::Unknown)?;
        // A malformed acknowledgement cannot undo a provider-side acceptance.
        // Preserve uncertainty so the durable host keeps the original command.
        command
            .decode_accepted(&bytes)
            .map_err(|_| ConnectorError::Unknown)
    }

    pub async fn observe(
        &self,
        command: &ProviderCommand,
        transfer: &str,
        token: &BearerToken,
    ) -> Result<Observation, ConnectorError> {
        command.validate()?;
        if !identifier(transfer, 50) {
            return Err(ConnectorError::Command);
        }
        let response = self
            .http
            .get(
                self.base_url
                    .join(&format!("transferRequests/{transfer}"))
                    .map_err(|_| ConnectorError::Configuration)?,
            )
            .header("Authorization", token.authorization_header_value())
            .header("X-Platform-TenantId", &self.connection.tenant)
            .header("X-billerId", &self.connection.biller)
            .header("X-CorrelationID", &command.request_id)
            .send()
            .await
            .map_err(|_| ConnectorError::Unavailable)?;
        let bytes = checked_response(response, Some(&command.request_id)).await?;
        command.decode_status(transfer, &bytes)
    }
}

async fn checked_response(
    response: reqwest::Response,
    correlation: Option<&str>,
) -> Result<Vec<u8>, ConnectorError> {
    if response.status().as_u16() != 200 {
        return Err(ConnectorError::Unavailable);
    }
    let header = |name: &str, expected: &str| {
        let values: Vec<_> = response.headers().get_all(name).iter().collect();
        values.len() == 1 && values[0].to_str().is_ok_and(|s| s == expected)
    };
    if !header("x-payment-simulator", "synthetic")
        || correlation.is_some_and(|id| !header("x-correlationid", id))
        || response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_none_or(|s| s.split(';').next() != Some("application/json"))
    {
        return Err(ConnectorError::Protocol);
    }
    registry_platform_httputil::read_bounded(response, RESPONSE_LIMIT)
        .await
        .map_err(|_| ConnectorError::Unavailable)
}

fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn identifier(value: &str, max: usize) -> bool {
    text(value, max)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
