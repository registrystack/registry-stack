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
//! policy preimage before accepting Relay's metadata identity. Relay is the
//! sole cryptographic and semantic verifier of the workload JWT on every
//! protected request.

use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::http::StatusCode;
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
    DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    DestinationAuthorizationValue, DestinationBodyTemplate, DestinationMethod,
    DestinationResponseError, DestinationSendError, ServiceHopDataDestinationPolicy,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_SERVICE_HOP_OPERATION_TIMEOUT,
};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
const MAX_CANONICAL_CONTRACT_BYTES: u32 = 64 * 1024;
const MAX_ACQUIRED_FIELDS: usize = 64;
const MAX_RESPONSE_SCHEMA_DEPTH: usize = 8;
const MAX_RESPONSE_SCHEMA_NODES: usize = 256;
const MAX_RESPONSE_SCHEMA_EXPANDED_NODES: usize = 4_096;
const MAX_RESPONSE_OBJECT_FIELDS: usize = 32;
const MAX_RESPONSE_ARRAY_ITEMS: u16 = 256;
const MAX_RESPONSE_FIELD_NAME_BYTES: usize = 128;
const MAX_JSON_INTEROPERABLE_INTEGER: u64 = (1_u64 << 53) - 1;
const PRESENCE_RESULT_GUARD_FIELD: &str = "__notary_presence_contract_guard";
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
const MAX_TOKEN_FILE_PATH_BYTES: usize = 4_096;
const MAX_TOKEN_FILE_BYTES: usize = TOKEN_MAX_BYTES + 2;

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

/// The exact public result contract Notary expects Relay to expose.
///
/// Presence-only is a first-class mode rather than an absent output name. It
/// can therefore be selected only by an exists-only claim journey and must be
/// confirmed by the hash-pinned Relay metadata before evaluations are served.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayExpectedResult {
    ProjectedString(RelayExpectedOutput),
    PresenceOnly,
}

impl RelayExpectedResult {
    /// Require one exact non-null string output.
    pub fn projected_string(name: impl Into<Box<str>>) -> Result<Self, RelayClientError> {
        RelayExpectedOutput::new(name).map(Self::ProjectedString)
    }
}

impl fmt::Debug for RelayExpectedResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayExpectedResult")
            .field("contract", &"[REDACTED]")
            .finish()
    }
}

/// A bounded reloadable workload-JWT file binding.
///
/// The path is restart-only. The current token is reopened, bounded,
/// structurally checked, and zeroized for every metadata or execution
/// operation, so atomic secret-file rotation requires no restart. Relay is the
/// sole cryptographic and semantic verifier.
pub struct RelayWorkloadCredentialFile {
    path: PathBuf,
    read_permit: Arc<Semaphore>,
}

impl RelayWorkloadCredentialFile {
    /// Freeze the reloadable credential-file reference.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, RelayClientError> {
        let path = path.into();
        if !valid_token_file_path(&path) {
            return Err(RelayClientError::InvalidConfiguration);
        }
        Ok(Self {
            path,
            read_permit: Arc::new(Semaphore::new(1)),
        })
    }

    async fn authorization(&self) -> Result<DestinationAuthorizationValue, RelayClientError> {
        let permit = Arc::clone(&self.read_permit)
            .acquire_owned()
            .await
            .map_err(|_| RelayClientError::CredentialUnavailable)?;
        let token = read_token_file(self.path.clone(), permit).await?;
        validate_compact_jws(&token)?;
        DestinationAuthorizationValue::bearer_zeroizing(token)
            .map_err(|_| RelayClientError::InvalidCredentials)
    }
}

impl fmt::Debug for RelayWorkloadCredentialFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayWorkloadCredentialFile")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

/// Unverified, fixed-origin client. Consume it with [`Self::verify_profile`]
/// before serving evaluations.
pub struct RelayConsultationClient {
    destination: ServiceHopDataDestinationPolicy,
    metadata_request: DataDestinationRequestTemplate,
    execute_request: DataDestinationRequestTemplate,
    metadata_decoder: ClosedJsonDecoder,
    credential: RelayWorkloadCredentialFile,
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_name: Box<str>,
    expected_result: RelayExpectedResult,
}

impl RelayConsultationClient {
    /// Freeze one Relay destination and one exact consultation route.
    pub fn new(
        destination: ServiceHopDataDestinationPolicy,
        credential: RelayWorkloadCredentialFile,
        pin: RelayProfilePin,
        purpose: impl Into<Box<str>>,
        input_name: impl Into<Box<str>>,
        expected_result: RelayExpectedResult,
    ) -> Result<Self, RelayClientError> {
        let purpose = purpose.into();
        let input_name = input_name.into();
        if !valid_purpose(&purpose) || !stable_id(&input_name, INPUT_NAME_MAX_BYTES) {
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
        let metadata_decoder = metadata_decoder()?;

        Ok(Self {
            destination,
            metadata_request,
            execute_request,
            metadata_decoder,
            credential,
            pin,
            purpose,
            input_name,
            expected_result,
        })
    }

    /// Authenticate to Relay, verify the pinned public profile, and compile
    /// the exact result contract used by runtime evaluations.
    pub async fn verify_profile(self) -> Result<VerifiedRelayClient, RelayClientError> {
        let profile = fetch_verified_profile(
            &self.destination,
            &self.metadata_request,
            &self.metadata_decoder,
            &self.credential,
            &self.pin,
            &self.purpose,
            &self.input_name,
            &self.expected_result,
        )
        .await?;
        let result_decoder = result_decoder(&profile)?;
        let max_in_flight = profile.max_in_flight;

        Ok(VerifiedRelayClient {
            destination: self.destination,
            metadata_request: self.metadata_request,
            execute_request: self.execute_request,
            metadata_decoder: self.metadata_decoder,
            result_decoder,
            credential: self.credential,
            permits: Semaphore::new(max_in_flight),
            profile,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_verified_profile(
    destination: &ServiceHopDataDestinationPolicy,
    metadata_request: &DataDestinationRequestTemplate,
    metadata_decoder: &ClosedJsonDecoder,
    credential: &RelayWorkloadCredentialFile,
    pin: &RelayProfilePin,
    purpose: &str,
    input_name: &str,
    expected_result: &RelayExpectedResult,
) -> Result<VerifiedRelayProfile, RelayClientError> {
    let deadline = operation_deadline()?;
    let authorization = authorization_before_deadline(credential, deadline).await?;
    let request = metadata_request
        .render(&[], &[], Some(authorization), None)
        .map_err(|_| RelayClientError::InvalidConfiguration)?;
    require_deadline(deadline)?;
    let response = destination
        .send_with_deadline(request, deadline)
        .await
        .map_err(map_send_error)?;
    require_deadline(deadline)?;
    require_success(response.status())?;
    response
        .require_exact_json_content_type()
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    require_deadline(deadline)?;
    let body = response
        .read_bounded(MAX_METADATA_BYTES)
        .await
        .map_err(|error| map_response_error(error, RelayClientError::InvalidProfileMetadata))?;
    require_deadline(deadline)?;
    let decoded = metadata_decoder
        .decode(body)
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    require_deadline(deadline)?;
    let ClosedJsonOutcome::One(record) = decoded else {
        return Err(RelayClientError::InvalidProfileMetadata);
    };
    let profile = parse_verified_profile(
        record.into_fields(),
        pin,
        purpose,
        input_name,
        expected_result,
    )?;
    require_deadline(deadline)?;
    Ok(profile)
}

impl fmt::Debug for RelayConsultationClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsultationClient")
            .field("destination", &"[REDACTED]")
            .field("route", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("contract", &"[REDACTED]")
            .finish()
    }
}

/// Startup-verified Relay client ready to serve evaluations.
pub struct VerifiedRelayClient {
    destination: ServiceHopDataDestinationPolicy,
    metadata_request: DataDestinationRequestTemplate,
    execute_request: DataDestinationRequestTemplate,
    metadata_decoder: ClosedJsonDecoder,
    result_decoder: ClosedJsonDecoder,
    credential: RelayWorkloadCredentialFile,
    permits: Semaphore,
    profile: VerifiedRelayProfile,
}

impl VerifiedRelayClient {
    /// Return the verified public profile snapshot used to validate results.
    #[must_use]
    pub const fn profile(&self) -> &VerifiedRelayProfile {
        &self.profile
    }

    /// Reload and validate the current credential, then re-fetch and verify
    /// the exact pinned metadata profile. Readiness uses this operation so a
    /// rotated or expired token cannot remain ready on stale startup state.
    pub async fn verify_current_profile(&self) -> Result<(), RelayClientError> {
        let expected_result = self.profile.result.expected();
        fetch_verified_profile(
            &self.destination,
            &self.metadata_request,
            &self.metadata_decoder,
            &self.credential,
            &self.profile.pin,
            &self.profile.purpose,
            &self.profile.input_name,
            &expected_result,
        )
        .await
        .map(|_| ())
    }

    /// Validate the caller-owned request fields without acquiring capacity,
    /// reading credentials, or touching the network.
    pub(crate) fn validate_execute_input(
        &self,
        evaluation_id: &str,
        input: &str,
    ) -> Result<(), RelayClientError> {
        if !canonical_ulid(evaluation_id)
            || input.is_empty()
            || input.len() > usize::from(self.profile.input_max_bytes)
            || input.len() > INPUT_VALUE_MAX_BYTES
            || input.chars().any(char::is_control)
            || !self.profile.input_pattern.is_match(input)
        {
            return Err(RelayClientError::InvalidRequest);
        }
        Ok(())
    }

    /// Execute one purpose-bound consultation. The evaluation id and input are
    /// validated before either value reaches the transport.
    pub async fn execute(
        &self,
        evaluation_id: &str,
        input: Zeroizing<String>,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        self.validate_execute_input(evaluation_id, &input)?;
        let deadline = operation_deadline()?;
        let _permit = timeout_at(deadline, self.permits.acquire())
            .await
            .map_err(|_| RelayClientError::Unavailable)?
            .map_err(|_| RelayClientError::CapacityUnavailable)?;
        require_deadline(deadline)?;

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

        require_deadline(deadline)?;
        let authorization = authorization_before_deadline(&self.credential, deadline).await?;
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
        require_deadline(deadline)?;
        let response = self
            .destination
            .send_with_deadline(request, deadline)
            .await
            .map_err(map_send_error)?;
        require_deadline(deadline)?;
        require_success(response.status())?;
        response
            .require_exact_json_content_type()
            .map_err(|_| RelayClientError::InvalidResult)?;
        require_deadline(deadline)?;
        let body = response
            .read_bounded(MAX_RESULT_BYTES)
            .await
            .map_err(|error| map_response_error(error, RelayClientError::InvalidResult))?;
        require_deadline(deadline)?;
        let decoded = self
            .result_decoder
            .decode(body)
            .map_err(|_| RelayClientError::InvalidResult)?;
        require_deadline(deadline)?;
        let ClosedJsonOutcome::One(record) = decoded else {
            return Err(RelayClientError::InvalidResult);
        };
        let result = parse_result(record.into_fields(), evaluation_id, &self.profile)?;
        require_deadline(deadline)?;
        Ok(result)
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
            .finish()
    }
}

/// Public metadata verified over the authenticated Relay connection.
pub struct VerifiedRelayProfile {
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_name: Box<str>,
    input_max_bytes: u16,
    max_in_flight: usize,
    input_pattern: BoundedInputPattern,
    acquisition_class: RelayAcquisitionClass,
    integration_pack: RelayArtifactIdentity,
    policy: RelayPolicyIdentity,
    result: VerifiedRelayResult,
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
    fn output_name(&self) -> Option<&str> {
        match &self.result {
            VerifiedRelayResult::ProjectedString(output) => Some(&output.name),
            VerifiedRelayResult::PresenceOnly => None,
        }
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

enum VerifiedRelayResult {
    ProjectedString(VerifiedRelayOutput),
    PresenceOnly,
}

impl VerifiedRelayResult {
    fn expected(&self) -> RelayExpectedResult {
        match self {
            Self::ProjectedString(output) => {
                RelayExpectedResult::ProjectedString(RelayExpectedOutput {
                    name: output.name.clone(),
                })
            }
            Self::PresenceOnly => RelayExpectedResult::PresenceOnly,
        }
    }
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

/// Match-only data contract verified against the pinned Relay profile.
pub(crate) enum RelayMatchData {
    ProjectedString(RelayOutputValue),
    PresenceOnly,
}

impl fmt::Debug for RelayMatchData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayMatchData([REDACTED])")
    }
}

/// Relay observation facts bound to one completed consultation.
pub struct RelayConsultationProvenance {
    relay_acquired_at: OffsetDateTime,
}

impl RelayConsultationProvenance {
    #[must_use]
    pub const fn relay_acquired_at(&self) -> OffsetDateTime {
        self.relay_acquired_at
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
    match_data: Option<RelayMatchData>,
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
    #[cfg(test)]
    pub const fn data(&self) -> Option<&RelayOutputValue> {
        match self.match_data.as_ref() {
            Some(RelayMatchData::ProjectedString(output)) => Some(output),
            Some(RelayMatchData::PresenceOnly) | None => None,
        }
    }

    #[must_use]
    pub(crate) const fn match_data(&self) -> Option<&RelayMatchData> {
        self.match_data.as_ref()
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
    #[error("Relay workload credential is unavailable")]
    CredentialUnavailable,
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

fn metadata_decoder() -> Result<ClosedJsonDecoder, RelayClientError> {
    let schema = object(
        false,
        vec![
            field("contract_hash", true, string(false, HASH_BYTES as u32)?)?,
            field(
                "contract_json",
                true,
                string(false, MAX_CANONICAL_CONTRACT_BYTES)?,
            )?,
        ],
    )?;
    ClosedJsonDecoder::new(
        schema,
        ClosedJsonRecordRoot::Object,
        vec![
            projection("m00", &["contract_hash"])?,
            projection("m01", &["contract_json"])?,
        ],
    )
    .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn result_decoder(profile: &VerifiedRelayProfile) -> Result<ClosedJsonDecoder, RelayClientError> {
    let data = match &profile.result {
        VerifiedRelayResult::ProjectedString(output) => object(
            true,
            vec![field(
                output.name.as_ref(),
                true,
                string(true, output.max_bytes)?,
            )?],
        )?,
        // The platform decoder intentionally rejects zero-field schemas. A
        // single optional guard lets it validate `{}` while the parser below
        // rejects the guard if it is ever present, preserving the exact empty
        // object contract without releasing response bytes.
        VerifiedRelayResult::PresenceOnly => object(
            true,
            vec![field(
                PRESENCE_RESULT_GUARD_FIELD,
                false,
                ClosedJsonSchema::boolean(false),
            )?],
        )?,
    };
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
    let mut projections = vec![
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
    ];
    let presence = match &profile.result {
        VerifiedRelayResult::ProjectedString(output) => {
            projections.push(projection("r22", &["data", output.name.as_ref()])?);
            vec![ClosedJsonPresenceProjection::new("r23", ["data"])
                .map_err(|_| RelayClientError::InvalidConfiguration)?]
        }
        VerifiedRelayResult::PresenceOnly => vec![
            ClosedJsonPresenceProjection::new("r22", ["data"])
                .map_err(|_| RelayClientError::InvalidConfiguration)?,
            ClosedJsonPresenceProjection::new("r23", ["data", PRESENCE_RESULT_GUARD_FIELD])
                .map_err(|_| RelayClientError::InvalidConfiguration)?,
        ],
    };
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
    expected_result: &RelayExpectedResult,
) -> Result<VerifiedRelayProfile, RelayClientError> {
    let mut fields = FieldCursor::new(fields, RelayClientError::InvalidProfileMetadata);
    let returned_contract_hash = fields.take_hash()?;
    let contract_json = fields.string()?;
    if !fields.exhausted() {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let contract_value = parse_json_strict(contract_json.as_bytes())
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    let canonical =
        canonicalize_json(&contract_value).map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    if canonical.as_slice() != contract_json.as_bytes() {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let computed_contract_hash = typed_json_hash(CONTRACT_HASH_DOMAIN, &contract_value)?;
    if returned_contract_hash.as_ref() != computed_contract_hash
        || pin.contract_hash() != computed_contract_hash
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let contract: RelayContractDocument = serde_json::from_value(contract_value)
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    validate_contract_document(contract, pin, purpose, input_name, expected_result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayContractDocument {
    schema: String,
    id: String,
    version: String,
    spec: RelayContractSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayContractSpec {
    subject: RelaySubjectContract,
    inputs: std::collections::BTreeMap<String, RelayInputContract>,
    integration_pack: RelayArtifactContract,
    acquisition: RelayAcquisitionContract,
    source_provenance: RelaySourceProvenanceContract,
    #[serde(default)]
    output_mode: RelayOutputMode,
    output: std::collections::BTreeMap<String, RelayOutputContract>,
    authorization: RelayAuthorizationContract,
    bounds: RelayBoundsContract,
    public_behavior: RelayPublicBehaviorContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySubjectContract {
    mode: String,
    selector_provenance: RelaySelectorProvenanceContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySelectorProvenanceContract {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayInputContract {
    #[serde(rename = "type")]
    kind: String,
    max_bytes: u16,
    pattern: String,
    canonicalization: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayArtifactContract {
    id: String,
    version: String,
    hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayAcquisitionContract {
    class: RelayAcquisitionClassContract,
    fields: std::collections::BTreeMap<String, RelayResponseSchemaContract>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayAcquisitionClassContract {
    SourceProjectedExact,
    BoundedFullRecord,
    MaterializedSnapshot,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RelayResponseSchemaContract {
    Object {
        nullable: bool,
        reject_unknown_fields: bool,
        fields: std::collections::BTreeMap<String, RelayResponseFieldContract>,
    },
    Array {
        nullable: bool,
        max_items: u16,
        items: Box<RelayResponseSchemaContract>,
    },
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayResponseFieldContract {
    required: bool,
    schema: Box<RelayResponseSchemaContract>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySourceProvenanceContract {
    source_observed_at: RelayAbsentContract,
    source_revision: RelayAbsentContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayAbsentContract {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayOutputMode {
    #[default]
    ProjectedFields,
    PresenceOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayOutputContract {
    #[serde(rename = "type")]
    kind: RelayOutputType,
    nullable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayOutputType {
    String,
    Boolean,
    Integer,
    Number,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayAuthorizationContract {
    workload: String,
    required_scope: String,
    purposes: Vec<String>,
    legal_basis: String,
    policy: RelayPolicyContract,
    consent: RelayConsentContract,
    mandatory_obligations: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayPolicyContract {
    id: String,
    hash: String,
    decision_cache: String,
    max_decision_age_ms: i64,
    unavailable: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayConsentContract {
    required: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayBoundsContract {
    max_source_matches: i64,
    max_disclosed_records: i64,
    max_data_exchanges: i64,
    max_credential_exchanges: i64,
    max_data_destinations: i64,
    max_source_bytes: i64,
    timeout_ms: i64,
    max_in_flight: i64,
    quota_per_minute: i64,
    quota_burst: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayPublicBehaviorContract {
    outcomes: Vec<String>,
    denial_code: String,
    denial_timing_profile: String,
}

fn validate_contract_document(
    contract: RelayContractDocument,
    pin: &RelayProfilePin,
    purpose: &str,
    input_name: &str,
    expected_result: &RelayExpectedResult,
) -> Result<VerifiedRelayProfile, RelayClientError> {
    if contract.schema != CONTRACT_SCHEMA
        || contract.id != pin.id()
        || contract.version != pin.version()
        || contract.spec.subject.mode != "single_subject"
        || contract.spec.subject.selector_provenance.kind != "workload_selected"
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let spec = contract.spec;
    let (returned_input_name, input) = spec
        .inputs
        .first_key_value()
        .filter(|_| spec.inputs.len() == 1)
        .ok_or(RelayClientError::InvalidProfileMetadata)?;
    if returned_input_name != input_name
        || input.kind != "string"
        || input.max_bytes == 0
        || usize::from(input.max_bytes) > INPUT_VALUE_MAX_BYTES
        || input.pattern.len() > MAX_BOUNDED_INPUT_PATTERN_BYTES
        || input.canonicalization != "identity"
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let input_pattern = BoundedInputPattern::compile(&input.pattern)
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;

    let pack = spec.integration_pack;
    if !stable_id(&pack.id, PROFILE_ID_MAX_BYTES)
        || !canonical_version(&pack.version)
        || !sha256_uri(&pack.hash)
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let acquisition_class = match spec.acquisition.class {
        RelayAcquisitionClassContract::SourceProjectedExact => {
            RelayAcquisitionClass::SourceProjectedExact
        }
        RelayAcquisitionClassContract::BoundedFullRecord => {
            RelayAcquisitionClass::BoundedFullRecord
        }
        RelayAcquisitionClassContract::MaterializedSnapshot => {
            return Err(RelayClientError::InvalidProfileMetadata)
        }
    };
    validate_acquisition_contract(&spec.acquisition.fields)?;
    if spec.source_provenance.source_observed_at.kind != "absent"
        || spec.source_provenance.source_revision.kind != "absent"
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    let authorization = spec.authorization;
    if authorization.workload != RELAY_WORKLOAD
        || !valid_scope(&authorization.required_scope)
        || authorization.purposes.as_slice() != [purpose]
        || !stable_id(&authorization.legal_basis, PROFILE_ID_MAX_BYTES)
        || authorization.policy.decision_cache != "disabled"
        || !(1..=10_000).contains(&authorization.policy.max_decision_age_ms)
        || authorization.policy.unavailable != "deny"
        || authorization.consent.required
        || !authorization.mandatory_obligations.is_empty()
        || !stable_id(&authorization.policy.id, PROFILE_ID_MAX_BYTES)
        || !sha256_uri(&authorization.policy.hash)
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let bounds = spec.bounds;
    if !(1..=2).contains(&bounds.max_source_matches)
        || bounds.max_disclosed_records != 1
        || !(1..=5).contains(&bounds.max_data_exchanges)
        || !(0..=1).contains(&bounds.max_credential_exchanges)
        || bounds.max_data_destinations != 1
        || !(1..=256 * 1024).contains(&bounds.max_source_bytes)
        || !(1..=10_000).contains(&bounds.timeout_ms)
        || !(1..=16).contains(&bounds.max_in_flight)
        || !(1..=60).contains(&bounds.quota_per_minute)
        || !(1..=10).contains(&bounds.quota_burst)
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let public_behavior = spec.public_behavior;
    if public_behavior.outcomes != ["match", "no_match", "ambiguous"]
        || public_behavior.denial_code != "consultation.denied"
        || public_behavior.denial_timing_profile.is_empty()
        || public_behavior.denial_timing_profile.len() > 64
        || public_behavior
            .denial_timing_profile
            .chars()
            .any(char::is_control)
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    let result = match (expected_result, spec.output_mode) {
        (RelayExpectedResult::ProjectedString(expected), RelayOutputMode::ProjectedFields) => {
            let output = spec
                .output
                .get(expected.name())
                .filter(|_| spec.output.len() == 1)
                .ok_or(RelayClientError::InvalidProfileMetadata)?;
            if output.kind != RelayOutputType::String || output.nullable {
                return Err(RelayClientError::InvalidProfileMetadata);
            }
            let RelayResponseSchemaContract::String {
                nullable,
                max_bytes,
            } = spec
                .acquisition
                .fields
                .get(expected.name())
                .ok_or(RelayClientError::InvalidProfileMetadata)?
            else {
                return Err(RelayClientError::InvalidProfileMetadata);
            };
            if *nullable || !(1..=MAX_PUBLIC_STRING_BYTES).contains(max_bytes) {
                return Err(RelayClientError::InvalidProfileMetadata);
            }
            VerifiedRelayResult::ProjectedString(VerifiedRelayOutput {
                name: expected.name().into(),
                max_bytes: *max_bytes,
            })
        }
        (RelayExpectedResult::PresenceOnly, RelayOutputMode::PresenceOnly)
            if spec.output.is_empty() =>
        {
            VerifiedRelayResult::PresenceOnly
        }
        _ => return Err(RelayClientError::InvalidProfileMetadata),
    };

    let integration_pack = json!({
        "id": pack.id.as_str(),
        "version": pack.version.as_str(),
        "hash": pack.hash.as_str(),
    });
    let consent = json!({"required": false});
    let policy_preimage = json!({
        "schema": POLICY_SCHEMA,
        "enforcement_profile": POLICY_ENFORCEMENT_PROFILE,
        "rule_set": POLICY_RULE_SET,
        "id": authorization.policy.id.as_str(),
        "action": POLICY_ACTION,
        "target": {
            "profile": {"id": pin.id(), "version": pin.version()},
            "integration_pack": integration_pack,
        },
        "authorization": {
            "workload": RELAY_WORKLOAD,
            "required_scope": authorization.required_scope.as_str(),
            "purposes": [purpose],
            "legal_basis": authorization.legal_basis.as_str(),
            "consent": consent,
            "mandatory_obligations": [],
        },
        "decision": {
            "permit": POLICY_PERMIT,
            "decision_cache": "disabled",
            "max_decision_age_ms": authorization.policy.max_decision_age_ms,
            "unavailable": "deny",
        },
    });
    if authorization.policy.hash != typed_json_hash(POLICY_HASH_DOMAIN, &policy_preimage)? {
        return Err(RelayClientError::InvalidProfileMetadata);
    }

    Ok(VerifiedRelayProfile {
        pin: pin.clone(),
        purpose: purpose.into(),
        input_name: input_name.into(),
        input_max_bytes: input.max_bytes,
        max_in_flight: usize::try_from(bounds.max_in_flight)
            .map_err(|_| RelayClientError::InvalidProfileMetadata)?,
        input_pattern,
        acquisition_class,
        integration_pack: RelayArtifactIdentity {
            id: pack.id.into_boxed_str(),
            version: pack.version.into_boxed_str(),
            hash: pack.hash.into_boxed_str(),
        },
        policy: RelayPolicyIdentity {
            id: authorization.policy.id.into_boxed_str(),
            hash: authorization.policy.hash.into_boxed_str(),
        },
        result,
    })
}

fn validate_acquisition_contract(
    fields: &std::collections::BTreeMap<String, RelayResponseSchemaContract>,
) -> Result<(), RelayClientError> {
    if fields.is_empty() || fields.len() > MAX_ACQUIRED_FIELDS {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    for (name, schema) in fields {
        if !stable_id(name, OUTPUT_NAME_MAX_BYTES) {
            return Err(RelayClientError::InvalidProfileMetadata);
        }
        let mut nodes = 0;
        let expanded = validate_response_schema_contract(schema, 1, &mut nodes)?;
        if expanded > MAX_RESPONSE_SCHEMA_EXPANDED_NODES {
            return Err(RelayClientError::InvalidProfileMetadata);
        }
    }
    Ok(())
}

fn validate_response_schema_contract(
    schema: &RelayResponseSchemaContract,
    depth: usize,
    nodes: &mut usize,
) -> Result<usize, RelayClientError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(RelayClientError::InvalidProfileMetadata)?;
    if depth > MAX_RESPONSE_SCHEMA_DEPTH || *nodes > MAX_RESPONSE_SCHEMA_NODES {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    match schema {
        RelayResponseSchemaContract::Object {
            nullable,
            reject_unknown_fields,
            fields,
        } => {
            let _ = nullable;
            if !reject_unknown_fields
                || fields.is_empty()
                || fields.len() > MAX_RESPONSE_OBJECT_FIELDS
            {
                return Err(RelayClientError::InvalidProfileMetadata);
            }
            let mut expanded = 1_usize;
            for (name, field) in fields {
                if name.is_empty()
                    || name.len() > MAX_RESPONSE_FIELD_NAME_BYTES
                    || name.chars().any(char::is_control)
                {
                    return Err(RelayClientError::InvalidProfileMetadata);
                }
                let _ = field.required;
                let child = validate_response_schema_contract(&field.schema, depth + 1, nodes)?;
                expanded = expanded
                    .checked_add(child)
                    .ok_or(RelayClientError::InvalidProfileMetadata)?;
            }
            Ok(expanded)
        }
        RelayResponseSchemaContract::Array {
            nullable,
            max_items,
            items,
        } => {
            let _ = nullable;
            if !(1..=MAX_RESPONSE_ARRAY_ITEMS).contains(max_items) {
                return Err(RelayClientError::InvalidProfileMetadata);
            }
            let child = validate_response_schema_contract(items, depth + 1, nodes)?;
            usize::from(*max_items)
                .checked_mul(child)
                .and_then(|expanded| expanded.checked_add(1))
                .ok_or(RelayClientError::InvalidProfileMetadata)
        }
        RelayResponseSchemaContract::String {
            nullable,
            max_bytes,
        } => {
            let _ = nullable;
            (1..=MAX_PUBLIC_STRING_BYTES)
                .contains(max_bytes)
                .then_some(1)
                .ok_or(RelayClientError::InvalidProfileMetadata)
        }
        RelayResponseSchemaContract::Boolean { nullable } => {
            let _ = nullable;
            Ok(1)
        }
        RelayResponseSchemaContract::Integer {
            nullable,
            minimum,
            maximum,
        }
        | RelayResponseSchemaContract::Number {
            nullable,
            minimum,
            maximum,
        } => {
            let _ = nullable;
            (*minimum <= *maximum
                && minimum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER
                && maximum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER)
                .then_some(1)
                .ok_or(RelayClientError::InvalidProfileMetadata)
        }
    }
}

fn parse_result(
    fields: Box<[ProjectedJsonField]>,
    evaluation_id: &str,
    profile: &VerifiedRelayProfile,
) -> Result<RelayConsultationResult, RelayClientError> {
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
    let match_data = match &profile.result {
        VerifiedRelayResult::ProjectedString(output) => {
            let scalar = fields.scalar()?;
            let data_present = fields.boolean()?;
            match (outcome, data_present, scalar) {
                (RelayConsultationOutcome::Match, true, ProjectedJsonScalar::String(value)) => {
                    Some(RelayMatchData::ProjectedString(RelayOutputValue {
                        name: output.name.clone(),
                        value,
                    }))
                }
                (
                    RelayConsultationOutcome::NoMatch | RelayConsultationOutcome::Ambiguous,
                    false,
                    ProjectedJsonScalar::Null,
                ) => None,
                _ => return Err(RelayClientError::InvalidResult),
            }
        }
        VerifiedRelayResult::PresenceOnly => {
            let data_present = fields.boolean()?;
            let guard_present = fields.boolean()?;
            if guard_present {
                return Err(RelayClientError::InvalidResult);
            }
            match (outcome, data_present) {
                (RelayConsultationOutcome::Match, true) => Some(RelayMatchData::PresenceOnly),
                (
                    RelayConsultationOutcome::NoMatch | RelayConsultationOutcome::Ambiguous,
                    false,
                ) => None,
                _ => return Err(RelayClientError::InvalidResult),
            }
        }
    };
    if !fields.exhausted() {
        return Err(RelayClientError::InvalidResult);
    }

    Ok(RelayConsultationResult {
        consultation_id,
        outcome,
        match_data,
        provenance: RelayConsultationProvenance { relay_acquired_at },
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

    fn require_null(&mut self) -> Result<(), RelayClientError> {
        matches!(self.scalar()?, ProjectedJsonScalar::Null)
            .then_some(())
            .ok_or(self.error)
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

fn string(nullable: bool, max_bytes: u32) -> Result<ClosedJsonSchema, RelayClientError> {
    ClosedJsonSchema::string(nullable, max_bytes)
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

async fn read_token_file(
    path: PathBuf,
    permit: OwnedSemaphorePermit,
) -> Result<Zeroizing<Vec<u8>>, RelayClientError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read_token_file_blocking(&path)
    })
    .await
    .map_err(|_| RelayClientError::CredentialUnavailable)?
}

fn read_token_file_blocking(path: &Path) -> Result<Zeroizing<Vec<u8>>, RelayClientError> {
    let file = open_token_file(path).map_err(|_| RelayClientError::CredentialUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RelayClientError::CredentialUnavailable)?;
    if !metadata.is_file() {
        return Err(RelayClientError::CredentialUnavailable);
    }
    if metadata.len() > MAX_TOKEN_FILE_BYTES as u64 {
        return Err(RelayClientError::InvalidCredentials);
    }
    let mut token = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(MAX_TOKEN_FILE_BYTES),
    ));
    file.take((MAX_TOKEN_FILE_BYTES + 1) as u64)
        .read_to_end(&mut token)
        .map_err(|_| RelayClientError::CredentialUnavailable)?;
    if token.len() > MAX_TOKEN_FILE_BYTES {
        return Err(RelayClientError::InvalidCredentials);
    }
    trim_one_line_ending(&mut token);
    if token.is_empty() || token.len() > TOKEN_MAX_BYTES {
        return Err(RelayClientError::InvalidCredentials);
    }
    Ok(token)
}

#[cfg(unix)]
fn open_token_file(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    // O_NONBLOCK makes opening a FIFO or device return promptly. We follow
    // symlinks so the conventional `..data`/atomic-symlink secret rotation
    // pattern remains supported, then fstat the opened descriptor and reject
    // every non-regular target before reading it.
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_token_file(path: &Path) -> std::io::Result<File> {
    // Supported production targets use the nonblocking Unix path. Other
    // targets still perform the same post-open regular-file and size checks.
    File::open(path)
}

fn trim_one_line_ending(value: &mut Vec<u8>) {
    if value.ends_with(b"\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with(b"\n") || value.ends_with(b"\r") {
        value.truncate(value.len() - 1);
    }
}

fn validate_compact_jws(token: &[u8]) -> Result<(), RelayClientError> {
    let mut segments = token.split(|byte| *byte == b'.');
    let header = segments
        .next()
        .ok_or(RelayClientError::InvalidCredentials)?;
    let claims = segments
        .next()
        .ok_or(RelayClientError::InvalidCredentials)?;
    let signature = segments
        .next()
        .ok_or(RelayClientError::InvalidCredentials)?;
    if segments.next().is_some()
        || !valid_base64url_segment(header)
        || !valid_base64url_segment(claims)
        || !valid_base64url_segment(signature)
    {
        return Err(RelayClientError::InvalidCredentials);
    }
    Ok(())
}

fn valid_base64url_segment(segment: &[u8]) -> bool {
    !segment.is_empty()
        && segment.len() % 4 != 1
        && segment
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

async fn authorization_before_deadline(
    credential: &RelayWorkloadCredentialFile,
    deadline: Instant,
) -> Result<DestinationAuthorizationValue, RelayClientError> {
    timeout_at(deadline, credential.authorization())
        .await
        .map_err(|_| RelayClientError::Unavailable)?
}

fn operation_deadline() -> Result<Instant, RelayClientError> {
    Instant::now()
        .checked_add(MAX_SERVICE_HOP_OPERATION_TIMEOUT)
        .ok_or(RelayClientError::InvalidConfiguration)
}

fn require_deadline(deadline: Instant) -> Result<(), RelayClientError> {
    if Instant::now() >= deadline {
        Err(RelayClientError::Unavailable)
    } else {
        Ok(())
    }
}

fn map_send_error(error: DestinationSendError) -> RelayClientError {
    match error {
        DestinationSendError::DeadlineExceeded => RelayClientError::Unavailable,
        _ => RelayClientError::TransportUnavailable,
    }
}

fn map_response_error(
    error: DestinationResponseError,
    otherwise: RelayClientError,
) -> RelayClientError {
    match error {
        DestinationResponseError::DeadlineExceeded => RelayClientError::Unavailable,
        _ => otherwise,
    }
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

fn valid_token_file_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    !text.is_empty()
        && text.len() <= MAX_TOKEN_FILE_PATH_BYTES
        && path.is_absolute()
        && path.file_name().is_some()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PURPOSE_MAX_BYTES
        && !value.contains(',')
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn canonical_ulid(value: &str) -> bool {
    Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}

#[cfg(test)]
mod tests;
