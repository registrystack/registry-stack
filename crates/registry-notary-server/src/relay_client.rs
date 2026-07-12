// SPDX-License-Identifier: Apache-2.0
//! Strict, single-origin Registry Relay consultation client.
//!
//! The client deliberately models one product journey rather than a generic
//! HTTP connector. Startup verifies one hash-pinned consultation profile over
//! the same authenticated Relay connection used for execution. Runtime calls
//! can then select only that profile's exact route, purpose, input, and closed
//! output fields.
//!
//! Notary independently re-hashes the narrowed public contract and its sole v1
//! policy preimage before accepting Relay's metadata identity. Relay remains
//! the cryptographic verifier of the typed workload JWT on every request.

use std::fmt;
use std::time::Duration;

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::destination::input_pattern::{
    BoundedInputPattern, MAX_BOUNDED_INPUT_BYTES, MAX_BOUNDED_INPUT_PATTERN_BYTES,
};
use registry_platform_httputil::destination::json::{
    ClosedJsonDecoder, ClosedJsonField, ClosedJsonOutcome, ClosedJsonPresenceProjection,
    ClosedJsonRecordRoot, ClosedJsonScalarProjection, ClosedJsonSchema, ProjectedJsonField,
    ProjectedJsonScalar,
};
use registry_platform_httputil::destination::{
    DataDestinationPolicy, DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    DestinationAuthorizationValue, DestinationBodyTemplate, DestinationMethod,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_DESTINATION_OPERATION_TIMEOUT,
};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Instant};
use ulid::Ulid;
use zeroize::Zeroizing;

const PROFILE_ID_MAX_BYTES: usize = 96;
const PROFILE_VERSION_MAX_BYTES: usize = 10;
const HASH_BYTES: usize = 71;
const PURPOSE_MAX_BYTES: usize = 256;
const INPUT_NAME_MAX_BYTES: usize = 96;
const INPUT_VALUE_MAX_BYTES: usize = MAX_BOUNDED_INPUT_BYTES as usize;
const OUTPUT_NAME_MAX_BYTES: usize = 96;
const TOKEN_MAX_BYTES: usize = MAX_DESTINATION_HEADER_VALUE_BYTES - "Bearer ".len();
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_WIRE_REQUEST_BYTES: usize = 18 * 1024;
const MAX_PUBLIC_STRING_BYTES: u32 = 64 * 1024;
const RELAY_WORKLOAD: &str = "registry-notary";
const CONTRACT_SCHEMA: &str = "registry.relay.consultation-contract.v1";
const RESULT_SCHEMA: &str = "registry.relay.consultation-result.v1";
const CONTRACT_HASH_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const POLICY_HASH_DOMAIN: &[u8] = b"registry.relay.consultation-policy.v1\0";
const POLICY_SCHEMA: &str = "registry.relay.consultation-policy.v1";
const POLICY_ENFORCEMENT_PROFILE: &str = "registry.relay.consultation-pdp/v1";
const POLICY_RULE_SET: &str = "registry.relay.consultation-policy-rules.v1";
const POLICY_ACTION: &str = "consultation_execute";
const POLICY_PERMIT: &str = "unqualified";
const JWT_CLAIM_MAX_BYTES: usize = 2_048;

/// The hash-pinned public profile identity selected at Notary startup.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayProfilePin {
    id: Box<str>,
    version: Box<str>,
    contract_hash: Box<str>,
}

impl RelayProfilePin {
    /// Validate one exact Relay profile path and public-contract identity.
    pub fn new(
        id: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
        contract_hash: impl Into<Box<str>>,
    ) -> Result<Self, RelayClientError> {
        let id = id.into();
        let version = version.into();
        let contract_hash = contract_hash.into();
        if !stable_id(&id, PROFILE_ID_MAX_BYTES)
            || !canonical_version(&version)
            || !sha256_uri(&contract_hash)
        {
            return Err(RelayClientError::InvalidConfiguration);
        }
        Ok(Self {
            id,
            version,
            contract_hash,
        })
    }

    /// Return the pinned profile id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the pinned profile version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the pinned public contract hash.
    #[must_use]
    pub fn contract_hash(&self) -> &str {
        &self.contract_hash
    }
}

impl fmt::Debug for RelayProfilePin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayProfilePin")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// The one configured string output that must exist in the verified profile.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayExpectedOutput {
    name: Box<str>,
}

impl RelayExpectedOutput {
    /// Validate the exact name of the required non-null string output.
    pub fn new(name: impl Into<Box<str>>) -> Result<Self, RelayClientError> {
        let name = name.into();
        if !stable_id(&name, OUTPUT_NAME_MAX_BYTES) {
            return Err(RelayClientError::InvalidConfiguration);
        }
        Ok(Self { name })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for RelayExpectedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayExpectedOutput")
            .field("name", &"[REDACTED]")
            .finish()
    }
}

/// A startup-validated compact JWT retained only in zeroizing memory.
///
/// Relay still verifies the JWS cryptographically. This local validation
/// prevents an opaque bearer, a token for another service, or a stale token
/// from becoming the Notary's activated workload credential.
pub struct RelayWorkloadCredential {
    token: Zeroizing<Vec<u8>>,
    expected_scope: Box<str>,
}

impl RelayWorkloadCredential {
    /// Validate the configured workload JWT against the exact deployment and
    /// profile binding expected by this Notary process.
    pub fn new(
        token: Zeroizing<Vec<u8>>,
        expected_issuer: &str,
        expected_audience: &str,
        expected_profile_scope: impl Into<Box<str>>,
    ) -> Result<Self, RelayClientError> {
        let expected_scope = expected_profile_scope.into();
        if !valid_claim_text(expected_issuer)
            || !valid_claim_text(expected_audience)
            || !valid_scope(&expected_scope)
            || token.is_empty()
            || token.len() > TOKEN_MAX_BYTES
        {
            return Err(RelayClientError::InvalidConfiguration);
        }
        validate_workload_jwt(
            &token,
            expected_issuer,
            expected_audience,
            &expected_scope,
            OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        DestinationAuthorizationValue::bearer_zeroizing(token.clone())
            .map_err(|_| RelayClientError::InvalidConfiguration)?;
        Ok(Self {
            token,
            expected_scope,
        })
    }

    fn authorization(&self) -> Result<DestinationAuthorizationValue, RelayClientError> {
        DestinationAuthorizationValue::bearer_zeroizing(self.token.clone())
            .map_err(|_| RelayClientError::InvalidConfiguration)
    }
}

impl fmt::Debug for RelayWorkloadCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayWorkloadCredential")
            .field("token", &"[REDACTED]")
            .field("claims", &"[REDACTED]")
            .finish()
    }
}

/// Unverified, fixed-origin client. Consume it with [`Self::verify_profile`]
/// before serving evaluations.
pub struct RelayConsultationClient {
    destination: DataDestinationPolicy,
    metadata_request: DataDestinationRequestTemplate,
    execute_request: DataDestinationRequestTemplate,
    metadata_decoder: ClosedJsonDecoder,
    credential: RelayWorkloadCredential,
    timeout: Duration,
    max_in_flight: usize,
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_name: Box<str>,
    expected_output: RelayExpectedOutput,
}

impl RelayConsultationClient {
    /// Freeze one Relay destination and one exact consultation route.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        destination: DataDestinationPolicy,
        credential: RelayWorkloadCredential,
        timeout: Duration,
        max_in_flight: usize,
        pin: RelayProfilePin,
        purpose: impl Into<Box<str>>,
        input_name: impl Into<Box<str>>,
        expected_output: RelayExpectedOutput,
    ) -> Result<Self, RelayClientError> {
        let purpose = purpose.into();
        let input_name = input_name.into();
        if timeout.is_zero()
            || timeout > MAX_DESTINATION_OPERATION_TIMEOUT
            || !(1..=16).contains(&max_in_flight)
            || !valid_purpose(&purpose)
            || !stable_id(&input_name, INPUT_NAME_MAX_BYTES)
        {
            return Err(RelayClientError::InvalidConfiguration);
        }

        let profile_path = format!("/v1/consultations/{}/versions/{}", pin.id, pin.version);
        let execute_path = format!("{profile_path}/execute");
        let metadata_request = DataDestinationRequestTemplate::new_with_exact_headers(
            DestinationMethod::Get,
            &profile_path,
            &[],
            &[("accept", b"application/json")],
            DestinationAuthorizationTemplate::Bearer {
                max_value_bytes: MAX_DESTINATION_HEADER_VALUE_BYTES,
            },
            DestinationBodyTemplate::Forbidden,
            MAX_WIRE_REQUEST_BYTES,
        )
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
        let execute_request = DataDestinationRequestTemplate::new(
            DestinationMethod::ReviewedReadOnlyPost,
            &execute_path,
            &[],
            &[
                ("accept", "application/json".len()),
                ("content-type", "application/json".len()),
                ("data-purpose", PURPOSE_MAX_BYTES),
                ("registry-notary-evaluation-id", 26),
            ],
            DestinationAuthorizationTemplate::Bearer {
                max_value_bytes: MAX_DESTINATION_HEADER_VALUE_BYTES,
            },
            DestinationBodyTemplate::Required {
                max_bytes: MAX_REQUEST_BYTES,
            },
            MAX_WIRE_REQUEST_BYTES,
        )
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
        let metadata_decoder = metadata_decoder(&input_name, &expected_output)?;

        Ok(Self {
            destination,
            metadata_request,
            execute_request,
            metadata_decoder,
            credential,
            timeout,
            max_in_flight,
            pin,
            purpose,
            input_name,
            expected_output,
        })
    }

    /// Authenticate to Relay, verify the pinned public profile, and compile
    /// the exact result contract used by runtime evaluations.
    pub async fn verify_profile(self) -> Result<VerifiedRelayClient, RelayClientError> {
        let deadline = operation_deadline(self.timeout)?;
        let authorization = self.credential.authorization()?;
        let request = self
            .metadata_request
            .render(&[], &[], Some(authorization), None)
            .map_err(|_| RelayClientError::InvalidConfiguration)?;
        let response = self
            .destination
            .send_with_deadline(request, deadline)
            .await
            .map_err(|_| RelayClientError::TransportUnavailable)?;
        require_success(response.status())?;
        response
            .require_exact_json_content_type()
            .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
        let body = response
            .read_bounded(MAX_METADATA_BYTES)
            .await
            .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
        let decoded = self
            .metadata_decoder
            .decode(body)
            .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
        let ClosedJsonOutcome::One(record) = decoded else {
            return Err(RelayClientError::InvalidProfileMetadata);
        };
        let profile = parse_verified_profile(
            record.into_fields(),
            &self.pin,
            &self.purpose,
            &self.input_name,
            &self.expected_output,
            &self.credential.expected_scope,
        )?;
        let result_decoder = result_decoder(&profile)?;

        Ok(VerifiedRelayClient {
            destination: self.destination,
            execute_request: self.execute_request,
            result_decoder,
            credential: self.credential,
            timeout: self.timeout,
            permits: Semaphore::new(self.max_in_flight),
            profile,
        })
    }
}

impl fmt::Debug for RelayConsultationClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsultationClient")
            .field("destination", &"[REDACTED]")
            .field("route", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("contract", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

/// Startup-verified Relay client ready to serve evaluations.
pub struct VerifiedRelayClient {
    destination: DataDestinationPolicy,
    execute_request: DataDestinationRequestTemplate,
    result_decoder: ClosedJsonDecoder,
    credential: RelayWorkloadCredential,
    timeout: Duration,
    permits: Semaphore,
    profile: VerifiedRelayProfile,
}

impl VerifiedRelayClient {
    /// Return the verified public profile snapshot used to validate results.
    #[must_use]
    pub const fn profile(&self) -> &VerifiedRelayProfile {
        &self.profile
    }

    /// Execute one purpose-bound consultation. The evaluation id and input are
    /// validated before either value reaches the transport.
    pub async fn execute(
        &self,
        evaluation_id: &str,
        input: Zeroizing<String>,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        if !canonical_ulid(evaluation_id)
            || input.is_empty()
            || input.len() > usize::from(self.profile.input_max_bytes)
            || input.len() > INPUT_VALUE_MAX_BYTES
            || input.chars().any(char::is_control)
            || !self.profile.input_pattern.is_match(&input)
        {
            return Err(RelayClientError::InvalidRequest);
        }
        let deadline = operation_deadline(self.timeout)?;
        let _permit = timeout_at(deadline, self.permits.acquire())
            .await
            .map_err(|_| RelayClientError::CapacityUnavailable)?
            .map_err(|_| RelayClientError::CapacityUnavailable)?;

        let mut body = Zeroizing::new(Vec::with_capacity(128));
        serde_json::to_writer(
            &mut *body,
            &ExecuteRequestBody {
                input_name: &self.profile.input_name,
                input_value: &input,
            },
        )
        .map_err(|_| RelayClientError::InvalidRequest)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(RelayClientError::InvalidRequest);
        }

        let authorization = self.credential.authorization()?;
        let headers: [&[u8]; 4] = [
            b"application/json",
            b"application/json",
            self.profile.purpose.as_bytes(),
            evaluation_id.as_bytes(),
        ];
        let request = self
            .execute_request
            .render_zeroizing(&[], &headers, Some(authorization), Some(body))
            .map_err(|_| RelayClientError::InvalidRequest)?;
        let response = self
            .destination
            .send_with_deadline(request, deadline)
            .await
            .map_err(|_| RelayClientError::TransportUnavailable)?;
        require_success(response.status())?;
        response
            .require_exact_json_content_type()
            .map_err(|_| RelayClientError::InvalidResult)?;
        let body = response
            .read_bounded(MAX_RESULT_BYTES)
            .await
            .map_err(|_| RelayClientError::InvalidResult)?;
        let decoded = self
            .result_decoder
            .decode(body)
            .map_err(|_| RelayClientError::InvalidResult)?;
        let ClosedJsonOutcome::One(record) = decoded else {
            return Err(RelayClientError::InvalidResult);
        };
        parse_result(record.into_fields(), evaluation_id, &self.profile)
    }
}

impl fmt::Debug for VerifiedRelayClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRelayClient")
            .field("destination", &"[REDACTED]")
            .field("route", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("profile", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Public metadata verified over the authenticated Relay connection.
pub struct VerifiedRelayProfile {
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_name: Box<str>,
    input_max_bytes: u16,
    input_pattern: BoundedInputPattern,
    acquisition_class: RelayAcquisitionClass,
    integration_pack: RelayArtifactIdentity,
    policy: RelayPolicyIdentity,
    output: VerifiedRelayOutput,
}

impl VerifiedRelayProfile {
    #[must_use]
    pub const fn pin(&self) -> &RelayProfilePin {
        &self.pin
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn input_name(&self) -> &str {
        &self.input_name
    }

    #[cfg(test)]
    fn output_name(&self) -> &str {
        &self.output.name
    }
}

impl fmt::Debug for VerifiedRelayProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRelayProfile")
            .field("identity", &"[REDACTED]")
            .field("purpose", &"[REDACTED]")
            .field("input", &"[REDACTED]")
            .field("output", &"[REDACTED]")
            .field("provenance", &"[REDACTED]")
            .finish()
    }
}

struct VerifiedRelayOutput {
    name: Box<str>,
    max_bytes: u32,
}

#[derive(Clone)]
struct RelayArtifactIdentity {
    id: Box<str>,
    version: Box<str>,
    hash: Box<str>,
}

#[derive(Clone)]
struct RelayPolicyIdentity {
    id: Box<str>,
    hash: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAcquisitionClass {
    SourceProjectedExact,
    BoundedFullRecord,
}

impl RelayAcquisitionClass {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::SourceProjectedExact => "source_projected_exact",
            Self::BoundedFullRecord => "bounded_full_record",
        }
    }
}

/// Closed Relay outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConsultationOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

/// Closed output name/value pair. Names and values are omitted from `Debug`.
pub struct RelayOutputValue {
    name: Box<str>,
    value: Zeroizing<String>,
}

impl RelayOutputValue {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for RelayOutputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayOutputValue")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Relay observation facts bound to one completed consultation.
pub struct RelayConsultationProvenance {
    relay_acquired_at: OffsetDateTime,
    acquisition_class: RelayAcquisitionClass,
}

impl RelayConsultationProvenance {
    #[must_use]
    pub const fn relay_acquired_at(&self) -> OffsetDateTime {
        self.relay_acquired_at
    }

    #[must_use]
    pub const fn acquisition_class(&self) -> RelayAcquisitionClass {
        self.acquisition_class
    }
}

impl fmt::Debug for RelayConsultationProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsultationProvenance")
            .field("facts", &"[REDACTED]")
            .finish()
    }
}

/// Strictly validated Relay consultation result.
pub struct RelayConsultationResult {
    consultation_id: Ulid,
    outcome: RelayConsultationOutcome,
    data: Option<RelayOutputValue>,
    provenance: RelayConsultationProvenance,
}

impl RelayConsultationResult {
    #[must_use]
    pub const fn consultation_id(&self) -> Ulid {
        self.consultation_id
    }

    #[must_use]
    pub const fn outcome(&self) -> RelayConsultationOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn data(&self) -> Option<&RelayOutputValue> {
        self.data.as_ref()
    }

    #[must_use]
    pub const fn provenance(&self) -> &RelayConsultationProvenance {
        &self.provenance
    }
}

impl fmt::Debug for RelayConsultationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsultationResult")
            .field("consultation_id", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .field("data", &"[REDACTED]")
            .field("provenance", &"[REDACTED]")
            .finish()
    }
}

/// Closed, value-free client failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RelayClientError {
    #[error("Relay client configuration is invalid")]
    InvalidConfiguration,
    #[error("Relay operation capacity is unavailable")]
    CapacityUnavailable,
    #[error("Relay transport is unavailable")]
    TransportUnavailable,
    #[error("Relay rejected its client credentials")]
    InvalidCredentials,
    #[error("Relay denied the consultation")]
    Denied,
    #[error("Relay consultation profile was not found")]
    ProfileNotFound,
    #[error("Relay rate-limited the consultation")]
    RateLimited,
    #[error("Relay consultation service is unavailable")]
    Unavailable,
    #[error("Relay returned an unexpected HTTP status")]
    UnexpectedStatus,
    #[error("Relay profile metadata is invalid")]
    InvalidProfileMetadata,
    #[error("Relay consultation request is invalid")]
    InvalidRequest,
    #[error("Relay consultation result is invalid")]
    InvalidResult,
}

struct ExecuteRequestBody<'a> {
    input_name: &'a str,
    input_value: &'a str,
}

impl Serialize for ExecuteRequestBody<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut root = serializer.serialize_struct("ConsultationExecuteRequest", 1)?;
        root.serialize_field("inputs", &SingleInput(self))?;
        root.end()
    }
}

struct SingleInput<'a>(&'a ExecuteRequestBody<'a>);

impl Serialize for SingleInput<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut inputs = serializer.serialize_map(Some(1))?;
        inputs.serialize_entry(self.0.input_name, self.0.input_value)?;
        inputs.end()
    }
}

// The remainder of this module compiles the exact consultation-v1 metadata
// and result schemas into the platform decoder. No raw response bytes cross
// this boundary.

fn metadata_decoder(
    input_name: &str,
    output: &RelayExpectedOutput,
) -> Result<ClosedJsonDecoder, RelayClientError> {
    let acquired_field = acquired_string_contract_schema()?;
    let public_output = object(
        false,
        vec![
            field("type", true, string(false, 16)?)?,
            field("nullable", true, ClosedJsonSchema::boolean(false))?,
        ],
    )?;
    let input = object(
        false,
        vec![
            field("type", true, string(false, 16)?)?,
            field(
                "max_bytes",
                true,
                integer(false, 1, INPUT_VALUE_MAX_BYTES as i64)?,
            )?,
            field(
                "pattern",
                true,
                string(false, MAX_BOUNDED_INPUT_PATTERN_BYTES as u32)?,
            )?,
            field("canonicalization", true, string(false, 32)?)?,
        ],
    )?;
    let subject = object(
        false,
        vec![
            field("mode", true, string(false, 32)?)?,
            field(
                "selector_provenance",
                true,
                object(false, vec![field("type", true, string(false, 32)?)?])?,
            )?,
        ],
    )?;
    let integration_pack = artifact_identity_schema()?;
    let acquisition = object(
        false,
        vec![
            field("class", true, string(false, 32)?)?,
            field(
                "fields",
                true,
                object(false, vec![field(output.name(), true, acquired_field)?])?,
            )?,
        ],
    )?;
    let source_provenance = object(
        false,
        vec![
            field(
                "source_observed_at",
                true,
                object(false, vec![field("type", true, string(false, 32)?)?])?,
            )?,
            field(
                "source_revision",
                true,
                object(false, vec![field("type", true, string(false, 32)?)?])?,
            )?,
        ],
    )?;
    let policy = object(
        false,
        vec![
            field("id", true, string(false, PROFILE_ID_MAX_BYTES as u32)?)?,
            field("hash", true, string(false, HASH_BYTES as u32)?)?,
            field("decision_cache", true, string(false, 16)?)?,
            field("max_decision_age_ms", true, integer(false, 1, 10_000)?)?,
            field("unavailable", true, string(false, 16)?)?,
        ],
    )?;
    let authorization = object(
        false,
        vec![
            field(
                "workload",
                true,
                string(false, PROFILE_ID_MAX_BYTES as u32)?,
            )?,
            field("required_scope", true, string(false, 256)?)?,
            field(
                "purposes",
                true,
                array(false, 1, string(false, PURPOSE_MAX_BYTES as u32)?)?,
            )?,
            field(
                "legal_basis",
                true,
                string(false, PROFILE_ID_MAX_BYTES as u32)?,
            )?,
            field("policy", true, policy)?,
            field(
                "consent",
                true,
                object(
                    false,
                    vec![field("required", true, ClosedJsonSchema::boolean(false))?],
                )?,
            )?,
            field(
                "mandatory_obligations",
                true,
                array(false, 1, string(false, 1)?)?,
            )?,
        ],
    )?;
    let bounds = object(
        false,
        vec![
            field("max_source_matches", true, integer(false, 1, 2)?)?,
            field("max_disclosed_records", true, integer(false, 1, 1)?)?,
            field("max_data_exchanges", true, integer(false, 1, 5)?)?,
            field("max_credential_exchanges", true, integer(false, 0, 1)?)?,
            field("max_data_destinations", true, integer(false, 1, 1)?)?,
            field("max_source_bytes", true, integer(false, 1, 256 * 1024)?)?,
            field("timeout_ms", true, integer(false, 1, 10_000)?)?,
            field("max_in_flight", true, integer(false, 1, 16)?)?,
            field("quota_per_minute", true, integer(false, 1, 60)?)?,
            field("quota_burst", true, integer(false, 1, 10)?)?,
        ],
    )?;
    let public_behavior = object(
        false,
        vec![
            field("outcomes", true, array(false, 3, string(false, 16)?)?)?,
            field("denial_code", true, string(false, 64)?)?,
            field("denial_timing_profile", true, string(false, 64)?)?,
        ],
    )?;
    let contract = object(
        false,
        vec![
            field("schema", true, string(false, 64)?)?,
            field("id", true, string(false, PROFILE_ID_MAX_BYTES as u32)?)?,
            field(
                "version",
                true,
                string(false, PROFILE_VERSION_MAX_BYTES as u32)?,
            )?,
            field(
                "spec",
                true,
                object(
                    false,
                    vec![
                        field("subject", true, subject)?,
                        field(
                            "inputs",
                            true,
                            object(false, vec![field(input_name, true, input)?])?,
                        )?,
                        field("integration_pack", true, integration_pack)?,
                        field("acquisition", true, acquisition)?,
                        field("source_provenance", true, source_provenance)?,
                        field(
                            "output",
                            true,
                            object(false, vec![field(output.name(), true, public_output)?])?,
                        )?,
                        field("authorization", true, authorization)?,
                        field("bounds", true, bounds)?,
                        field("public_behavior", true, public_behavior)?,
                    ],
                )?,
            )?,
        ],
    )?;
    let schema = object(
        false,
        vec![
            field("contract_hash", true, string(false, HASH_BYTES as u32)?)?,
            field("contract", true, contract)?,
        ],
    )?;

    let output_name = output.name();
    let mut projections = vec![
        projection("m00", &["contract_hash"])?,
        projection("m01", &["contract", "schema"])?,
        projection("m02", &["contract", "id"])?,
        projection("m03", &["contract", "version"])?,
        projection("m04", &["contract", "spec", "subject", "mode"])?,
        projection(
            "m05",
            &["contract", "spec", "subject", "selector_provenance", "type"],
        )?,
        projection("m06", &["contract", "spec", "inputs", input_name, "type"])?,
        projection(
            "m07",
            &["contract", "spec", "inputs", input_name, "max_bytes"],
        )?,
        projection(
            "m08",
            &["contract", "spec", "inputs", input_name, "pattern"],
        )?,
        projection(
            "m09",
            &["contract", "spec", "inputs", input_name, "canonicalization"],
        )?,
        projection("m10", &["contract", "spec", "integration_pack", "id"])?,
        projection("m11", &["contract", "spec", "integration_pack", "version"])?,
        projection("m12", &["contract", "spec", "integration_pack", "hash"])?,
        projection("m13", &["contract", "spec", "acquisition", "class"])?,
        projection(
            "m14",
            &[
                "contract",
                "spec",
                "acquisition",
                "fields",
                output_name,
                "type",
            ],
        )?,
        projection(
            "m15",
            &[
                "contract",
                "spec",
                "acquisition",
                "fields",
                output_name,
                "nullable",
            ],
        )?,
    ];
    projections.push(projection(
        "m16",
        &[
            "contract",
            "spec",
            "acquisition",
            "fields",
            output_name,
            "max_bytes",
        ],
    )?);
    let next = projections.len();
    for (offset, tokens) in [
        vec![
            "contract",
            "spec",
            "source_provenance",
            "source_observed_at",
            "type",
        ],
        vec![
            "contract",
            "spec",
            "source_provenance",
            "source_revision",
            "type",
        ],
        vec!["contract", "spec", "output", output_name, "type"],
        vec!["contract", "spec", "output", output_name, "nullable"],
        vec!["contract", "spec", "authorization", "workload"],
        vec!["contract", "spec", "authorization", "required_scope"],
        vec!["contract", "spec", "authorization", "purposes", "0"],
        vec!["contract", "spec", "authorization", "legal_basis"],
        vec!["contract", "spec", "authorization", "policy", "id"],
        vec!["contract", "spec", "authorization", "policy", "hash"],
        vec![
            "contract",
            "spec",
            "authorization",
            "policy",
            "decision_cache",
        ],
        vec![
            "contract",
            "spec",
            "authorization",
            "policy",
            "max_decision_age_ms",
        ],
        vec!["contract", "spec", "authorization", "policy", "unavailable"],
        vec!["contract", "spec", "authorization", "consent", "required"],
        vec!["contract", "spec", "bounds", "max_source_matches"],
        vec!["contract", "spec", "bounds", "max_disclosed_records"],
        vec!["contract", "spec", "bounds", "max_data_exchanges"],
        vec!["contract", "spec", "bounds", "max_credential_exchanges"],
        vec!["contract", "spec", "bounds", "max_data_destinations"],
        vec!["contract", "spec", "bounds", "max_source_bytes"],
        vec!["contract", "spec", "bounds", "timeout_ms"],
        vec!["contract", "spec", "bounds", "max_in_flight"],
        vec!["contract", "spec", "bounds", "quota_per_minute"],
        vec!["contract", "spec", "bounds", "quota_burst"],
        vec!["contract", "spec", "public_behavior", "outcomes", "0"],
        vec!["contract", "spec", "public_behavior", "outcomes", "1"],
        vec!["contract", "spec", "public_behavior", "outcomes", "2"],
        vec!["contract", "spec", "public_behavior", "denial_code"],
        vec![
            "contract",
            "spec",
            "public_behavior",
            "denial_timing_profile",
        ],
    ]
    .into_iter()
    .enumerate()
    {
        projections.push(projection(&format!("m{:02}", next + offset), &tokens)?);
    }
    let presence = vec![ClosedJsonPresenceProjection::new(
        "m99",
        [
            "contract",
            "spec",
            "authorization",
            "mandatory_obligations",
            "0",
        ],
    )
    .map_err(|_| RelayClientError::InvalidConfiguration)?];
    ClosedJsonDecoder::new_with_presence(
        schema,
        ClosedJsonRecordRoot::Object,
        projections,
        presence,
    )
    .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn result_decoder(profile: &VerifiedRelayProfile) -> Result<ClosedJsonDecoder, RelayClientError> {
    let output = &profile.output;
    let data_value = string(true, output.max_bytes)?;
    let data = object(true, vec![field(output.name.as_ref(), true, data_value)?])?;
    let provenance = object(
        false,
        vec![
            field("relay_acquired_at", true, string(false, 64)?)?,
            field("source_observed_at", true, string(true, 64)?)?,
            field(
                "source_revision",
                true,
                string(true, MAX_PUBLIC_STRING_BYTES)?,
            )?,
            field("acquisition_class", true, string(false, 32)?)?,
            field("integration_pack", true, artifact_identity_schema()?)?,
            field(
                "policy_id",
                true,
                string(false, PROFILE_ID_MAX_BYTES as u32)?,
            )?,
            field("policy_hash", true, string(false, HASH_BYTES as u32)?)?,
            field(
                "consent",
                true,
                object(
                    false,
                    vec![
                        field("outcome", true, string(false, 32)?)?,
                        field(
                            "verifier_id",
                            true,
                            string(true, PROFILE_ID_MAX_BYTES as u32)?,
                        )?,
                        field("verifier_revision", true, string(true, HASH_BYTES as u32)?)?,
                        field("checked_at", true, string(true, 64)?)?,
                        field("expires_at", true, string(true, 64)?)?,
                        field("revocation_status", true, string(false, 32)?)?,
                    ],
                )?,
            )?,
        ],
    )?;
    let schema = object(
        false,
        vec![
            field("schema", true, string(false, 64)?)?,
            field("consultation_id", true, string(false, 26)?)?,
            field("notary_evaluation_id", true, string(false, 26)?)?,
            field(
                "profile",
                true,
                object(
                    false,
                    vec![
                        field("id", true, string(false, PROFILE_ID_MAX_BYTES as u32)?)?,
                        field(
                            "version",
                            true,
                            string(false, PROFILE_VERSION_MAX_BYTES as u32)?,
                        )?,
                        field("contract_hash", true, string(false, HASH_BYTES as u32)?)?,
                    ],
                )?,
            )?,
            field("outcome", true, string(false, 16)?)?,
            field("data", true, data)?,
            field("provenance", true, provenance)?,
        ],
    )?;
    let projections = vec![
        projection("r00", &["schema"])?,
        projection("r01", &["consultation_id"])?,
        projection("r02", &["notary_evaluation_id"])?,
        projection("r03", &["profile", "id"])?,
        projection("r04", &["profile", "version"])?,
        projection("r05", &["profile", "contract_hash"])?,
        projection("r06", &["outcome"])?,
        projection("r07", &["provenance", "relay_acquired_at"])?,
        projection("r08", &["provenance", "source_observed_at"])?,
        projection("r09", &["provenance", "source_revision"])?,
        projection("r10", &["provenance", "acquisition_class"])?,
        projection("r11", &["provenance", "integration_pack", "id"])?,
        projection("r12", &["provenance", "integration_pack", "version"])?,
        projection("r13", &["provenance", "integration_pack", "hash"])?,
        projection("r14", &["provenance", "policy_id"])?,
        projection("r15", &["provenance", "policy_hash"])?,
        projection("r16", &["provenance", "consent", "outcome"])?,
        projection("r17", &["provenance", "consent", "verifier_id"])?,
        projection("r18", &["provenance", "consent", "verifier_revision"])?,
        projection("r19", &["provenance", "consent", "checked_at"])?,
        projection("r20", &["provenance", "consent", "expires_at"])?,
        projection("r21", &["provenance", "consent", "revocation_status"])?,
        projection("r22", &["data", output.name.as_ref()])?,
    ];
    let presence = vec![ClosedJsonPresenceProjection::new("r23", ["data"])
        .map_err(|_| RelayClientError::InvalidConfiguration)?];
    ClosedJsonDecoder::new_with_presence(
        schema,
        ClosedJsonRecordRoot::Object,
        projections,
        presence,
    )
    .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn parse_verified_profile(
    fields: Box<[ProjectedJsonField]>,
    pin: &RelayProfilePin,
    purpose: &str,
    input_name: &str,
    expected_output: &RelayExpectedOutput,
    expected_scope: &str,
) -> Result<VerifiedRelayProfile, RelayClientError> {
    let mut fields = FieldCursor::new(fields, RelayClientError::InvalidProfileMetadata);
    let returned_contract_hash = fields.take_hash()?;
    fields.require_string(CONTRACT_SCHEMA)?;
    fields.require_string(pin.id())?;
    fields.require_string(pin.version())?;
    fields.require_string("single_subject")?;
    fields.require_string("workload_selected")?;
    fields.require_string("string")?;
    let input_max_bytes = fields.integer()?;
    let input_max_bytes = u16::try_from(input_max_bytes)
        .ok()
        .filter(|value| usize::from(*value) <= INPUT_VALUE_MAX_BYTES)
        .ok_or(RelayClientError::InvalidProfileMetadata)?;
    let pattern = fields.string()?;
    let input_pattern = BoundedInputPattern::compile(&pattern)
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    fields.require_string("identity")?;
    let integration_pack_id = fields.take_bounded_id()?;
    let integration_pack_version = fields.take_version()?;
    let integration_pack_hash = fields.take_hash()?;
    let acquisition_class_text = fields.string()?;
    let acquisition_class = match acquisition_class_text.as_str() {
        "source_projected_exact" => RelayAcquisitionClass::SourceProjectedExact,
        "bounded_full_record" => RelayAcquisitionClass::BoundedFullRecord,
        _ => return Err(RelayClientError::InvalidProfileMetadata),
    };
    fields.require_string("string")?;
    fields.require_boolean(false)?;
    let max_bytes = u32::try_from(fields.integer()?)
        .ok()
        .filter(|value| (1..=MAX_PUBLIC_STRING_BYTES).contains(value))
        .ok_or(RelayClientError::InvalidProfileMetadata)?;
    fields.require_string("absent")?;
    fields.require_string("absent")?;
    fields.require_string("string")?;
    fields.require_boolean(false)?;
    fields.require_string(RELAY_WORKLOAD)?;
    let required_scope = fields.string()?;
    if required_scope.as_str() != expected_scope {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    fields.require_string(purpose)?;
    let legal_basis = fields.string()?;
    if legal_basis.is_empty() {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let policy_id = fields.take_bounded_id()?;
    let policy_hash = fields.take_hash()?;
    fields.require_string("disabled")?;
    let max_decision_age_ms = fields.integer()?;
    fields.require_string("deny")?;
    fields.require_boolean(false)?;
    let max_source_matches = fields.integer()?;
    let max_disclosed_records = fields.integer()?;
    let max_data_exchanges = fields.integer()?;
    let max_credential_exchanges = fields.integer()?;
    let max_data_destinations = fields.integer()?;
    let max_source_bytes = fields.integer()?;
    let timeout_ms = fields.integer()?;
    let max_in_flight = fields.integer()?;
    let quota_per_minute = fields.integer()?;
    let quota_burst = fields.integer()?;
    fields.require_string("match")?;
    fields.require_string("no_match")?;
    fields.require_string("ambiguous")?;
    fields.require_string("consultation.denied")?;
    let denial_timing = fields.string()?;
    if denial_timing.is_empty() {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    fields.require_boolean(false)?;
    if !fields.exhausted() {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    // The platform decoder has independently strict-parsed the response,
    // rejected every undeclared member, and projected every scalar in the
    // closed contract. Reconstructing that complete value makes the JCS hash
    // independent of Relay's returned digest while keeping raw response bytes
    // inside the platform-owned decoder.
    let integration_pack = json!({
        "id": integration_pack_id.as_ref(),
        "version": integration_pack_version.as_ref(),
        "hash": integration_pack_hash.as_ref(),
    });
    let consent = json!({"required": false});
    let contract = json!({
        "schema": CONTRACT_SCHEMA,
        "id": pin.id(),
        "version": pin.version(),
        "spec": {
            "subject": {
                "mode": "single_subject",
                "selector_provenance": {"type": "workload_selected"},
            },
            "inputs": single_json_member(input_name, json!({
                "type": "string",
                "max_bytes": input_max_bytes,
                "pattern": pattern.as_str(),
                "canonicalization": "identity",
            })),
            "integration_pack": integration_pack.clone(),
            "acquisition": {
                "class": acquisition_class_text.as_str(),
                "fields": single_json_member(expected_output.name(), json!({
                    "type": "string",
                    "nullable": false,
                    "max_bytes": max_bytes,
                })),
            },
            "source_provenance": {
                "source_observed_at": {"type": "absent"},
                "source_revision": {"type": "absent"},
            },
            "output": single_json_member(expected_output.name(), json!({
                "type": "string",
                "nullable": false,
            })),
            "authorization": {
                "workload": RELAY_WORKLOAD,
                "required_scope": required_scope.as_str(),
                "purposes": [purpose],
                "legal_basis": legal_basis.as_str(),
                "policy": {
                    "id": policy_id.as_ref(),
                    "hash": policy_hash.as_ref(),
                    "decision_cache": "disabled",
                    "max_decision_age_ms": max_decision_age_ms,
                    "unavailable": "deny",
                },
                "consent": consent.clone(),
                "mandatory_obligations": [],
            },
            "bounds": {
                "max_source_matches": max_source_matches,
                "max_disclosed_records": max_disclosed_records,
                "max_data_exchanges": max_data_exchanges,
                "max_credential_exchanges": max_credential_exchanges,
                "max_data_destinations": max_data_destinations,
                "max_source_bytes": max_source_bytes,
                "timeout_ms": timeout_ms,
                "max_in_flight": max_in_flight,
                "quota_per_minute": quota_per_minute,
                "quota_burst": quota_burst,
            },
            "public_behavior": {
                "outcomes": ["match", "no_match", "ambiguous"],
                "denial_code": "consultation.denied",
                "denial_timing_profile": denial_timing.as_str(),
            },
        },
    });
    let computed_contract_hash = typed_json_hash(CONTRACT_HASH_DOMAIN, &contract)?;
    if returned_contract_hash.as_ref() != computed_contract_hash
        || pin.contract_hash() != computed_contract_hash
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    let policy_preimage = json!({
        "schema": POLICY_SCHEMA,
        "enforcement_profile": POLICY_ENFORCEMENT_PROFILE,
        "rule_set": POLICY_RULE_SET,
        "id": policy_id.as_ref(),
        "action": POLICY_ACTION,
        "target": {
            "profile": {"id": pin.id(), "version": pin.version()},
            "integration_pack": integration_pack,
        },
        "authorization": {
            "workload": RELAY_WORKLOAD,
            "required_scope": required_scope.as_str(),
            "purposes": [purpose],
            "legal_basis": legal_basis.as_str(),
            "consent": consent,
            "mandatory_obligations": [],
        },
        "decision": {
            "permit": POLICY_PERMIT,
            "decision_cache": "disabled",
            "max_decision_age_ms": max_decision_age_ms,
            "unavailable": "deny",
        },
    });
    if policy_hash.as_ref() != typed_json_hash(POLICY_HASH_DOMAIN, &policy_preimage)? {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    Ok(VerifiedRelayProfile {
        pin: pin.clone(),
        purpose: purpose.into(),
        input_name: input_name.into(),
        input_max_bytes,
        input_pattern,
        acquisition_class,
        integration_pack: RelayArtifactIdentity {
            id: integration_pack_id,
            version: integration_pack_version,
            hash: integration_pack_hash,
        },
        policy: RelayPolicyIdentity {
            id: policy_id,
            hash: policy_hash,
        },
        output: VerifiedRelayOutput {
            name: expected_output.name.clone(),
            max_bytes,
        },
    })
}

fn parse_result(
    fields: Box<[ProjectedJsonField]>,
    evaluation_id: &str,
    profile: &VerifiedRelayProfile,
) -> Result<RelayConsultationResult, RelayClientError> {
    let output = &profile.output;
    let mut fields = FieldCursor::new(fields, RelayClientError::InvalidResult);
    fields.require_string(RESULT_SCHEMA)?;
    let consultation_id_text = fields.string()?;
    let consultation_id = Ulid::from_string(&consultation_id_text)
        .ok()
        .filter(|id| id.to_string() == consultation_id_text.as_str())
        .ok_or(RelayClientError::InvalidResult)?;
    fields.require_string(evaluation_id)?;
    fields.require_string(profile.pin.id())?;
    fields.require_string(profile.pin.version())?;
    fields.require_string(profile.pin.contract_hash())?;
    let outcome = match fields.string()?.as_str() {
        "match" => RelayConsultationOutcome::Match,
        "no_match" => RelayConsultationOutcome::NoMatch,
        "ambiguous" => RelayConsultationOutcome::Ambiguous,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let acquired_at = fields.string()?;
    let relay_acquired_at = OffsetDateTime::parse(&acquired_at, &Rfc3339)
        .map_err(|_| RelayClientError::InvalidResult)?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_string(profile.acquisition_class.wire_name())?;
    fields.require_string(&profile.integration_pack.id)?;
    fields.require_string(&profile.integration_pack.version)?;
    fields.require_string(&profile.integration_pack.hash)?;
    fields.require_string(&profile.policy.id)?;
    fields.require_string(&profile.policy.hash)?;
    fields.require_string("not_required")?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_string("not_applicable")?;
    let scalar = fields.scalar()?;
    let data_present = fields.boolean()?;
    if !fields.exhausted() {
        return Err(RelayClientError::InvalidResult);
    }
    let data = match (outcome, data_present, scalar) {
        (RelayConsultationOutcome::Match, true, ProjectedJsonScalar::String(value)) => {
            Some(RelayOutputValue {
                name: output.name.clone(),
                value,
            })
        }
        (
            RelayConsultationOutcome::NoMatch | RelayConsultationOutcome::Ambiguous,
            false,
            ProjectedJsonScalar::Null,
        ) => None,
        _ => return Err(RelayClientError::InvalidResult),
    };

    Ok(RelayConsultationResult {
        consultation_id,
        outcome,
        data,
        provenance: RelayConsultationProvenance {
            relay_acquired_at,
            acquisition_class: profile.acquisition_class,
        },
    })
}

struct FieldCursor {
    fields: std::vec::IntoIter<ProjectedJsonField>,
    error: RelayClientError,
}

impl FieldCursor {
    fn new(fields: Box<[ProjectedJsonField]>, error: RelayClientError) -> Self {
        Self {
            fields: Vec::from(fields).into_iter(),
            error,
        }
    }

    fn scalar(&mut self) -> Result<ProjectedJsonScalar, RelayClientError> {
        self.fields
            .next()
            .map(ProjectedJsonField::into_parts)
            .map(|(_, value)| value)
            .ok_or(self.error)
    }

    fn string(&mut self) -> Result<Zeroizing<String>, RelayClientError> {
        match self.scalar()? {
            ProjectedJsonScalar::String(value) => Ok(value),
            _ => Err(self.error),
        }
    }

    fn integer(&mut self) -> Result<i64, RelayClientError> {
        match self.scalar()? {
            ProjectedJsonScalar::Integer(value) => Ok(value),
            _ => Err(self.error),
        }
    }

    fn boolean(&mut self) -> Result<bool, RelayClientError> {
        match self.scalar()? {
            ProjectedJsonScalar::Boolean(value) => Ok(value),
            _ => Err(self.error),
        }
    }

    fn require_string(&mut self, expected: &str) -> Result<(), RelayClientError> {
        (self.string()?.as_str() == expected)
            .then_some(())
            .ok_or(self.error)
    }

    fn require_boolean(&mut self, expected: bool) -> Result<(), RelayClientError> {
        (self.boolean()? == expected)
            .then_some(())
            .ok_or(self.error)
    }

    fn require_null(&mut self) -> Result<(), RelayClientError> {
        matches!(self.scalar()?, ProjectedJsonScalar::Null)
            .then_some(())
            .ok_or(self.error)
    }

    fn take_bounded_id(&mut self) -> Result<Box<str>, RelayClientError> {
        let mut value = self.string()?;
        if !stable_id(&value, PROFILE_ID_MAX_BYTES) {
            return Err(RelayClientError::InvalidProfileMetadata);
        }
        Ok(std::mem::take(&mut *value).into_boxed_str())
    }

    fn take_version(&mut self) -> Result<Box<str>, RelayClientError> {
        let mut value = self.string()?;
        if !canonical_version(&value) {
            return Err(RelayClientError::InvalidProfileMetadata);
        }
        Ok(std::mem::take(&mut *value).into_boxed_str())
    }

    fn take_hash(&mut self) -> Result<Box<str>, RelayClientError> {
        let mut value = self.string()?;
        if !sha256_uri(&value) {
            return Err(RelayClientError::InvalidProfileMetadata);
        }
        Ok(std::mem::take(&mut *value).into_boxed_str())
    }

    fn exhausted(&self) -> bool {
        self.fields.as_slice().is_empty()
    }
}

fn acquired_string_contract_schema() -> Result<ClosedJsonSchema, RelayClientError> {
    object(
        false,
        vec![
            field("type", true, string(false, 16)?)?,
            field("nullable", true, ClosedJsonSchema::boolean(false))?,
            field(
                "max_bytes",
                true,
                integer(false, 1, i64::from(MAX_PUBLIC_STRING_BYTES))?,
            )?,
        ],
    )
}

fn artifact_identity_schema() -> Result<ClosedJsonSchema, RelayClientError> {
    object(
        false,
        vec![
            field("id", true, string(false, PROFILE_ID_MAX_BYTES as u32)?)?,
            field(
                "version",
                true,
                string(false, PROFILE_VERSION_MAX_BYTES as u32)?,
            )?,
            field("hash", true, string(false, HASH_BYTES as u32)?)?,
        ],
    )
}

fn object(
    nullable: bool,
    fields: Vec<ClosedJsonField>,
) -> Result<ClosedJsonSchema, RelayClientError> {
    ClosedJsonSchema::object(nullable, fields).map_err(|_| RelayClientError::InvalidConfiguration)
}

fn array(
    nullable: bool,
    max_items: u16,
    items: ClosedJsonSchema,
) -> Result<ClosedJsonSchema, RelayClientError> {
    ClosedJsonSchema::array(nullable, max_items, items)
        .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn string(nullable: bool, max_bytes: u32) -> Result<ClosedJsonSchema, RelayClientError> {
    ClosedJsonSchema::string(nullable, max_bytes)
        .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn integer(
    nullable: bool,
    minimum: i64,
    maximum: i64,
) -> Result<ClosedJsonSchema, RelayClientError> {
    ClosedJsonSchema::integer(nullable, minimum, maximum)
        .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn field(
    name: &str,
    required: bool,
    schema: ClosedJsonSchema,
) -> Result<ClosedJsonField, RelayClientError> {
    ClosedJsonField::new(name, required, schema).map_err(|_| RelayClientError::InvalidConfiguration)
}

fn projection(name: &str, tokens: &[&str]) -> Result<ClosedJsonScalarProjection, RelayClientError> {
    ClosedJsonScalarProjection::new(name, tokens.iter().copied())
        .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn single_json_member(name: &str, value: Value) -> Value {
    let mut object = Map::new();
    object.insert(name.to_owned(), value);
    Value::Object(object)
}

fn typed_json_hash(domain: &[u8], value: &Value) -> Result<String, RelayClientError> {
    let canonical =
        canonicalize_json(value).map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(HASH_BYTES);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn validate_workload_jwt(
    token: &[u8],
    expected_issuer: &str,
    expected_audience: &str,
    expected_scope: &str,
    now: i64,
) -> Result<(), RelayClientError> {
    let compact = std::str::from_utf8(token).map_err(|_| RelayClientError::InvalidConfiguration)?;
    let mut segments = compact.split('.');
    let header_segment = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or(RelayClientError::InvalidConfiguration)?;
    let claims_segment = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or(RelayClientError::InvalidConfiguration)?;
    let signature_segment = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or(RelayClientError::InvalidConfiguration)?;
    if segments.next().is_some() {
        return Err(RelayClientError::InvalidConfiguration);
    }

    let header_bytes = decode_jwt_segment(header_segment)?;
    let claims_bytes = decode_jwt_segment(claims_segment)?;
    let signature_bytes = decode_jwt_segment(signature_segment)?;
    if signature_bytes.is_empty() {
        return Err(RelayClientError::InvalidConfiguration);
    }
    let header =
        parse_json_strict(&header_bytes).map_err(|_| RelayClientError::InvalidConfiguration)?;
    let claims =
        parse_json_strict(&claims_bytes).map_err(|_| RelayClientError::InvalidConfiguration)?;
    drop(header_bytes);
    drop(claims_bytes);
    drop(signature_bytes);
    validate_jwt_header(&header)?;
    validate_jwt_claims(
        &claims,
        expected_issuer,
        expected_audience,
        expected_scope,
        now,
    )
}

fn decode_jwt_segment(segment: &str) -> Result<Zeroizing<Vec<u8>>, RelayClientError> {
    if !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(RelayClientError::InvalidConfiguration);
    }
    let capacity = segment
        .len()
        .checked_mul(3)
        .and_then(|length| length.checked_div(4))
        .and_then(|length| length.checked_add(3))
        .ok_or(RelayClientError::InvalidConfiguration)?;
    let mut decoded = Zeroizing::new(vec![0_u8; capacity]);
    let length = URL_SAFE_NO_PAD
        .decode_slice(segment.as_bytes(), &mut decoded)
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
    decoded.truncate(length);
    Ok(decoded)
}

fn validate_jwt_header(value: &Value) -> Result<(), RelayClientError> {
    let object = closed_json_object(value, &["alg", "kid", "typ"])?;
    let alg = required_json_string(object, "alg")?;
    if !matches!(alg, "RS256" | "ES256" | "EdDSA")
        || required_json_string(object, "typ")? != "at+jwt"
        || !valid_claim_text(required_json_string(object, "kid")?)
    {
        return Err(RelayClientError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_jwt_claims(
    value: &Value,
    expected_issuer: &str,
    expected_audience: &str,
    expected_scope: &str,
    now: i64,
) -> Result<(), RelayClientError> {
    let object = closed_json_object(
        value,
        &[
            "aud",
            "azp",
            "client_id",
            "exp",
            "iat",
            "iss",
            "nbf",
            "scope",
            "sub",
        ],
    )?;
    if required_json_string(object, "iss")? != expected_issuer
        || required_json_string(object, "sub")? != RELAY_WORKLOAD
        || required_json_string(object, "scope")? != expected_scope
        || !exact_json_audience(
            object
                .get("aud")
                .ok_or(RelayClientError::InvalidConfiguration)?,
            expected_audience,
        )
    {
        return Err(RelayClientError::InvalidConfiguration);
    }

    let azp = optional_json_string(object, "azp")?;
    let client_id = optional_json_string(object, "client_id")?;
    if (azp.is_none() && client_id.is_none())
        || azp.is_some_and(|value| value != RELAY_WORKLOAD)
        || client_id.is_some_and(|value| value != RELAY_WORKLOAD)
    {
        return Err(RelayClientError::InvalidConfiguration);
    }

    let issued_at = required_json_i64(object, "iat")?;
    let expires_at = required_json_i64(object, "exp")?;
    let not_before = optional_json_i64(object, "nbf")?;
    if issued_at < 0
        || issued_at > now
        || expires_at <= now
        || expires_at <= issued_at
        || not_before.is_some_and(|value| value < 0 || value > now || value >= expires_at)
    {
        return Err(RelayClientError::InvalidConfiguration);
    }
    Ok(())
}

fn closed_json_object<'a>(
    value: &'a Value,
    allowed_fields: &[&str],
) -> Result<&'a Map<String, Value>, RelayClientError> {
    let object = value
        .as_object()
        .ok_or(RelayClientError::InvalidConfiguration)?;
    if object
        .keys()
        .any(|name| !allowed_fields.contains(&name.as_str()))
    {
        return Err(RelayClientError::InvalidConfiguration);
    }
    Ok(object)
}

fn required_json_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, RelayClientError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| valid_claim_text(value))
        .ok_or(RelayClientError::InvalidConfiguration)
}

fn optional_json_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, RelayClientError> {
    object
        .get(name)
        .map(|value| {
            value
                .as_str()
                .filter(|value| valid_claim_text(value))
                .ok_or(RelayClientError::InvalidConfiguration)
        })
        .transpose()
}

fn required_json_i64(object: &Map<String, Value>, name: &str) -> Result<i64, RelayClientError> {
    object
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(RelayClientError::InvalidConfiguration)
}

fn optional_json_i64(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<i64>, RelayClientError> {
    object
        .get(name)
        .map(|value| value.as_i64().ok_or(RelayClientError::InvalidConfiguration))
        .transpose()
}

fn exact_json_audience(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => {
            matches!(values.as_slice(), [Value::String(value)] if value == expected)
        }
        _ => false,
    }
}

fn operation_deadline(timeout: Duration) -> Result<Instant, RelayClientError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(RelayClientError::InvalidConfiguration)
}

fn require_success(status: StatusCode) -> Result<(), RelayClientError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::BAD_REQUEST => Err(RelayClientError::InvalidRequest),
        StatusCode::UNAUTHORIZED => Err(RelayClientError::InvalidCredentials),
        StatusCode::FORBIDDEN => Err(RelayClientError::Denied),
        StatusCode::NOT_FOUND => Err(RelayClientError::ProfileNotFound),
        StatusCode::TOO_MANY_REQUESTS => Err(RelayClientError::RateLimited),
        StatusCode::SERVICE_UNAVAILABLE => Err(RelayClientError::Unavailable),
        _ => Err(RelayClientError::UnexpectedStatus),
    }
}

fn stable_id(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn canonical_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PROFILE_VERSION_MAX_BYTES
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|version| version > 0)
}

fn sha256_uri(value: &str) -> bool {
    value.len() == HASH_BYTES
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_purpose(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PURPOSE_MAX_BYTES
        && !value.contains(',')
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn valid_claim_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= JWT_CLAIM_MAX_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn valid_scope(value: &str) -> bool {
    value.len() <= PURPOSE_MAX_BYTES && valid_claim_text(value) && !value.contains(',')
}

fn canonical_ulid(value: &str) -> bool {
    Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}

#[cfg(test)]
mod tests;
