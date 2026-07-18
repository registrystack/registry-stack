// SPDX-License-Identifier: Apache-2.0
//! Strict, single-origin Registry Relay consultation client.
//!
//! Startup verifies one hash-pinned consultation profile over the same
//! authenticated Relay connection used for execution. Runtime calls can then
//! select only that profile's exact route, purpose, input, and closed typed
//! output map.
//!
//! Notary independently re-hashes the narrowed public contract before
//! accepting Relay's metadata identity. Relay is the sole cryptographic and
//! semantic verifier of the workload JWT on every protected request.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::http::StatusCode;
use registry_notary_core::{
    is_rfc3339_full_date, RelayOutputContract as NotaryRelayOutputContract,
};
use registry_platform_httputil::destination::input_pattern::MAX_BOUNDED_INPUT_BYTES;
use registry_platform_httputil::destination::json::{
    decode_typed_hash_envelope_as, ClosedJsonDecoder, ClosedJsonField, ClosedJsonOutcome,
    ClosedJsonPresenceProjection, ClosedJsonRecordRoot, ClosedJsonScalarProjection,
    ClosedJsonSchema, ProjectedJsonField, ProjectedJsonScalar,
};
use registry_platform_httputil::destination::{
    DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    DestinationAuthorizationValue, DestinationBodyTemplate, DestinationMethod,
    DestinationResponseError, DestinationSendError, ServiceHopDataDestinationPolicy,
    MAX_DESTINATION_HEADER_VALUE_BYTES, MAX_SERVICE_HOP_OPERATION_TIMEOUT,
};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Serialize, Serializer};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::relay_contract::{
    verify_contract, RelayPublicContract, VerifiedAcquisitionClass, VerifiedContractSemantics,
    VerifiedInputType, VerifiedSourceField, CONTRACT_HASH_DOMAIN,
};

const PROFILE_ID_MAX_BYTES: usize = 96;
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
const MAX_ACQUIRED_FIELDS: usize = 64;
const MAX_JSON_INTEROPERABLE_INTEGER: u64 = (1_u64 << 53) - 1;
const RESULT_SCHEMA: &str = "registry.relay.consultation-result.v1";
const MAX_TOKEN_FILE_PATH_BYTES: usize = 4_096;
const MAX_TOKEN_FILE_BYTES: usize = TOKEN_MAX_BYTES + 2;
const BATCH_CHILD_IDENTITY_MAX_BYTES: usize = 43;
const DEFAULT_MAX_IN_FLIGHT: usize = 8;
const MAX_CONFIGURED_IN_FLIGHT: usize = 64;

/// The hash-pinned public profile identity selected at Notary startup.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayProfilePin {
    id: Box<str>,
    contract_hash: Box<str>,
}

impl RelayProfilePin {
    /// Validate one exact Relay profile path and public-contract identity.
    pub fn new(
        id: impl Into<Box<str>>,
        contract_hash: impl Into<Box<str>>,
    ) -> Result<Self, RelayClientError> {
        let id = id.into();
        let contract_hash = contract_hash.into();
        if !stable_id(&id, PROFILE_ID_MAX_BYTES) || !sha256_uri(&contract_hash) {
            return Err(RelayClientError::InvalidConfiguration);
        }
        Ok(Self { id, contract_hash })
    }

    /// Return the pinned profile id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
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

/// The exact public result contract Notary expects Relay to expose.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayExpectedResult {
    OutputMap(BTreeMap<String, NotaryRelayOutputContract>),
}

impl RelayExpectedResult {
    /// Require one complete closed typed output map.
    pub fn output_map(
        outputs: BTreeMap<String, NotaryRelayOutputContract>,
    ) -> Result<Self, RelayClientError> {
        if outputs.len() > MAX_ACQUIRED_FIELDS
            || outputs.iter().any(|(name, output)| {
                !output_name(name, OUTPUT_NAME_MAX_BYTES)
                    || matches!(name.as_str(), "matched" | "outcome")
                    || !valid_output(output)
            })
        {
            return Err(RelayClientError::InvalidConfiguration);
        }
        Ok(Self::OutputMap(outputs))
    }
}

fn valid_output(output: &NotaryRelayOutputContract) -> bool {
    match output {
        NotaryRelayOutputContract::String { max_bytes, .. } => {
            (1..=MAX_PUBLIC_STRING_BYTES).contains(max_bytes)
        }
        NotaryRelayOutputContract::Integer {
            minimum, maximum, ..
        } => {
            minimum <= maximum
                && *minimum >= -(MAX_JSON_INTEROPERABLE_INTEGER as i64)
                && *maximum <= MAX_JSON_INTEROPERABLE_INTEGER as i64
        }
        NotaryRelayOutputContract::Boolean { .. } | NotaryRelayOutputContract::Date { .. } => true,
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
    execute_batch_request: DataDestinationRequestTemplate,
    credential: RelayWorkloadCredentialFile,
    workload_client_id: Box<str>,
    pin: RelayProfilePin,
    purpose: Box<str>,
    input_names: Box<[String]>,
    expected_result: RelayExpectedResult,
    max_in_flight: usize,
}

#[doc(hidden)]
pub enum RelayInputNames {
    One(String),
    Many(Vec<String>),
}

impl From<&str> for RelayInputNames {
    fn from(value: &str) -> Self {
        Self::One(value.to_string())
    }
}

impl From<String> for RelayInputNames {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

impl From<Vec<String>> for RelayInputNames {
    fn from(value: Vec<String>) -> Self {
        Self::Many(value)
    }
}

impl RelayInputNames {
    pub(crate) fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

impl RelayConsultationClient {
    /// Freeze one Relay destination and one exact consultation route.
    pub fn new(
        destination: ServiceHopDataDestinationPolicy,
        credential: RelayWorkloadCredentialFile,
        workload_client_id: impl Into<Box<str>>,
        pin: RelayProfilePin,
        purpose: impl Into<Box<str>>,
        input_names: impl Into<RelayInputNames>,
        expected_result: RelayExpectedResult,
    ) -> Result<Self, RelayClientError> {
        let workload_client_id = workload_client_id.into();
        let purpose = purpose.into();
        let mut input_names = input_names.into().into_vec();
        input_names.sort();
        input_names.dedup();
        if !stable_id(&workload_client_id, PROFILE_ID_MAX_BYTES)
            || !valid_purpose(&purpose)
            || !(1..=16).contains(&input_names.len())
            || input_names
                .iter()
                .any(|name| !stable_id(name, INPUT_NAME_MAX_BYTES))
        {
            return Err(RelayClientError::InvalidConfiguration);
        }

        let profile_path = format!("/v1/consultations/{}", pin.id);
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
        let execute_batch_request = DataDestinationRequestTemplate::new(
            DestinationMethod::ReviewedReadOnlyPost,
            &execute_path,
            &[],
            &[
                ("accept", "application/json".len()),
                ("content-type", "application/json".len()),
                ("data-purpose", PURPOSE_MAX_BYTES),
                ("registry-notary-evaluation-id", 26),
                (
                    "registry-notary-batch-child-id",
                    BATCH_CHILD_IDENTITY_MAX_BYTES,
                ),
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
        Ok(Self {
            destination,
            metadata_request,
            execute_request,
            execute_batch_request,
            credential,
            workload_client_id,
            pin,
            purpose,
            input_names: input_names.into_boxed_slice(),
            expected_result,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        })
    }

    /// Apply the operator-owned cap for concurrent calls to the pinned Relay profile.
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Result<Self, RelayClientError> {
        if !(1..=MAX_CONFIGURED_IN_FLIGHT).contains(&max_in_flight) {
            return Err(RelayClientError::InvalidConfiguration);
        }
        self.max_in_flight = max_in_flight;
        Ok(self)
    }

    /// Authenticate to Relay, verify the pinned public profile, and compile
    /// the exact result contract used by runtime evaluations.
    pub async fn verify_profile(self) -> Result<VerifiedRelayClient, RelayClientError> {
        let profile = fetch_verified_profile(
            &self.destination,
            &self.metadata_request,
            &self.credential,
            &self.pin,
            &self.workload_client_id,
            &self.purpose,
            &self.input_names,
            &self.expected_result,
            self.max_in_flight,
        )
        .await?;
        let result_decoder = result_decoder(&profile)?;
        let max_in_flight = profile.max_in_flight;

        Ok(VerifiedRelayClient {
            destination: self.destination,
            metadata_request: self.metadata_request,
            execute_request: self.execute_request,
            execute_batch_request: self.execute_batch_request,
            result_decoder,
            credential: self.credential,
            workload_client_id: self.workload_client_id,
            permits: Semaphore::new(max_in_flight),
            profile,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_verified_profile(
    destination: &ServiceHopDataDestinationPolicy,
    metadata_request: &DataDestinationRequestTemplate,
    credential: &RelayWorkloadCredentialFile,
    pin: &RelayProfilePin,
    workload_client_id: &str,
    purpose: &str,
    input_names: &[String],
    expected_result: &RelayExpectedResult,
    max_in_flight: usize,
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
    let envelope = decode_typed_hash_envelope_as::<RelayPublicContract>(body, CONTRACT_HASH_DOMAIN)
        .map_err(|_| RelayClientError::InvalidProfileMetadata)?;
    if envelope.advertised_hash() != pin.contract_hash()
        || envelope.computed_hash() != pin.contract_hash()
    {
        return Err(RelayClientError::InvalidProfileMetadata);
    }
    let contract = envelope.into_contract();
    let RelayExpectedResult::OutputMap(outputs) = expected_result;
    let semantics = verify_contract(
        contract,
        pin.id(),
        workload_client_id,
        purpose,
        input_names,
        outputs,
    )
    .map_err(|()| RelayClientError::InvalidProfileMetadata)?;
    let result = VerifiedRelayResult::OutputMap(outputs.clone());
    let profile = VerifiedRelayProfile {
        pin: pin.clone(),
        purpose: purpose.to_string().into_boxed_str(),
        input_names: input_names.to_vec().into_boxed_slice(),
        max_in_flight,
        result,
        semantics,
    };
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
    execute_batch_request: DataDestinationRequestTemplate,
    result_decoder: ClosedJsonDecoder,
    credential: RelayWorkloadCredentialFile,
    workload_client_id: Box<str>,
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
            &self.credential,
            &self.profile.pin,
            &self.workload_client_id,
            &self.profile.purpose,
            &self.profile.input_names,
            &expected_result,
            self.profile.max_in_flight,
        )
        .await
        .map(|_| ())
    }

    /// Validate the caller-owned request fields without acquiring capacity,
    /// reading credentials, or touching the network.
    pub(crate) fn canonicalize_execute_inputs(
        &self,
        evaluation_id: &str,
        inputs: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<BTreeMap<String, Zeroizing<String>>, RelayClientError> {
        if !canonical_ulid(evaluation_id)
            || inputs.len() != self.profile.input_names.len()
            || inputs.keys().ne(self.profile.input_names.iter())
        {
            return Err(RelayClientError::InvalidRequest);
        }
        let mut canonical = BTreeMap::new();
        for name in &self.profile.input_names {
            let value = inputs.get(name).ok_or(RelayClientError::InvalidRequest)?;
            let input_type = self
                .profile
                .semantics
                .input_types
                .get(name)
                .ok_or(RelayClientError::InvalidConfiguration)?;
            if value.is_empty()
                || value.len() > INPUT_VALUE_MAX_BYTES
                || value.chars().any(char::is_control)
                || !valid_wire_input(value, *input_type)
            {
                return Err(RelayClientError::InvalidRequest);
            }
            canonical.insert(name.clone(), Zeroizing::new(value.to_string()));
        }
        Ok(canonical)
    }

    /// Execute one purpose-bound consultation. The evaluation id and input are
    /// validated before either value reaches the transport.
    #[allow(dead_code)]
    pub async fn execute(
        &self,
        evaluation_id: &str,
        input: Zeroizing<String>,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        let Some(input_name) = self.profile.input_names.first() else {
            return Err(RelayClientError::InvalidConfiguration);
        };
        if self.profile.input_names.len() != 1 {
            return Err(RelayClientError::InvalidRequest);
        }
        self.execute_inputs(evaluation_id, BTreeMap::from([(input_name.clone(), input)]))
            .await
    }

    pub(crate) async fn execute_inputs(
        &self,
        evaluation_id: &str,
        inputs: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        self.execute_inputs_with_batch_child(evaluation_id, inputs, None)
            .await
    }

    pub(crate) async fn execute_batch_inputs(
        &self,
        evaluation_id: &str,
        inputs: BTreeMap<String, Zeroizing<String>>,
        batch_child_identity: &str,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        if batch_child_identity.len() != BATCH_CHILD_IDENTITY_MAX_BYTES
            || !batch_child_identity
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RelayClientError::InvalidRequest);
        }
        self.execute_inputs_with_batch_child(evaluation_id, inputs, Some(batch_child_identity))
            .await
    }

    async fn execute_inputs_with_batch_child(
        &self,
        evaluation_id: &str,
        inputs: BTreeMap<String, Zeroizing<String>>,
        batch_child_identity: Option<&str>,
    ) -> Result<RelayConsultationResult, RelayClientError> {
        let inputs = self.canonicalize_execute_inputs(evaluation_id, &inputs)?;
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
                contract_hash: self.profile.pin.contract_hash(),
                inputs: &inputs,
                input_types: &self.profile.semantics.input_types,
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
        let batch_headers: [&[u8]; 5] = [
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            batch_child_identity.unwrap_or_default().as_bytes(),
        ];
        let request = match batch_child_identity {
            Some(_) => self.execute_batch_request.render_zeroizing(
                &[],
                &batch_headers,
                Some(authorization),
                Some(body),
            ),
            None => self.execute_request.render_zeroizing(
                &[],
                &headers,
                Some(authorization),
                Some(body),
            ),
        }
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
    input_names: Box<[String]>,
    max_in_flight: usize,
    result: VerifiedRelayResult,
    semantics: VerifiedContractSemantics,
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
    pub fn input_names(&self) -> &[String] {
        &self.input_names
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

enum VerifiedRelayResult {
    OutputMap(BTreeMap<String, NotaryRelayOutputContract>),
}

impl VerifiedRelayResult {
    fn expected(&self) -> RelayExpectedResult {
        let Self::OutputMap(outputs) = self;
        RelayExpectedResult::OutputMap(outputs.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAcquisitionClass {
    SourceProjectedExact,
    BoundedFullRecord,
    MaterializedSnapshot,
}

/// Closed Relay outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConsultationOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

/// Match-only output contract verified against the pinned Relay profile.
pub(crate) enum RelayMatchData {
    OutputMap(RelayOutputMap),
}

pub(crate) struct RelayOutputMap {
    fields: BTreeMap<Box<str>, ProjectedJsonScalar>,
}

impl RelayOutputMap {
    pub(crate) fn fields(&self) -> impl ExactSizeIterator<Item = (&str, &ProjectedJsonScalar)> {
        self.fields
            .iter()
            .map(|(name, value)| (name.as_ref(), value))
    }
}

impl fmt::Debug for RelayOutputMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayOutputMap")
            .field("fields", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for RelayMatchData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayMatchData([REDACTED])")
    }
}

/// Relay observation outputs bound to one completed consultation.
pub struct RelayConsultationProvenance {
    acquired_at: OffsetDateTime,
}

impl RelayConsultationProvenance {
    #[must_use]
    pub const fn acquired_at(&self) -> OffsetDateTime {
        self.acquired_at
    }
}

impl fmt::Debug for RelayConsultationProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsultationProvenance")
            .field("outputs", &"[REDACTED]")
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
            .field("outputs", &"[REDACTED]")
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
    #[error("Relay consultation contract does not match the pinned contract")]
    ContractMismatch,
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
    contract_hash: &'a str,
    inputs: &'a BTreeMap<String, Zeroizing<String>>,
    input_types: &'a BTreeMap<String, VerifiedInputType>,
}

impl Serialize for ExecuteRequestBody<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut root = serializer.serialize_struct("ConsultationExecuteRequest", 2)?;
        root.serialize_field("contract_hash", self.contract_hash)?;
        root.serialize_field("inputs", &SerializableInputs(self.inputs, self.input_types))?;
        root.end()
    }
}

struct SerializableInputs<'a>(
    &'a BTreeMap<String, Zeroizing<String>>,
    &'a BTreeMap<String, VerifiedInputType>,
);

impl Serialize for SerializableInputs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in self.0 {
            let input_type = self
                .1
                .get(name)
                .ok_or_else(|| serde::ser::Error::custom("verified input type is absent"))?;
            map.serialize_entry(
                name,
                &SerializableInputValue {
                    value,
                    input_type: *input_type,
                },
            )?;
        }
        map.end()
    }
}

struct SerializableInputValue<'a> {
    value: &'a str,
    input_type: VerifiedInputType,
}

impl Serialize for SerializableInputValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.input_type {
            VerifiedInputType::String => serializer.serialize_str(self.value),
            VerifiedInputType::Boolean => match self.value {
                "true" => serializer.serialize_bool(true),
                "false" => serializer.serialize_bool(false),
                _ => Err(serde::ser::Error::custom(
                    "Boolean consultation input is not canonical",
                )),
            },
            VerifiedInputType::Integer => self
                .value
                .parse::<i64>()
                .ok()
                .filter(|value| value.to_string() == self.value)
                .ok_or_else(|| {
                    serde::ser::Error::custom("Integer consultation input is not canonical")
                })?
                .serialize(serializer),
        }
    }
}

fn valid_wire_input(value: &str, input_type: VerifiedInputType) -> bool {
    match input_type {
        VerifiedInputType::String => true,
        VerifiedInputType::Boolean => matches!(value, "true" | "false"),
        VerifiedInputType::Integer => value
            .parse::<i64>()
            .is_ok_and(|parsed| parsed.to_string() == value),
    }
}

// The remainder of this module compiles the exact consultation-v1 result
// schema into the platform decoder. No unvalidated response bytes cross this
// boundary.

fn result_decoder(profile: &VerifiedRelayProfile) -> Result<ClosedJsonDecoder, RelayClientError> {
    let VerifiedRelayResult::OutputMap(outputs) = &profile.result;
    let output_fields = if outputs.is_empty() {
        vec![field(
            "__registry_notary_empty_output_sentinel",
            false,
            ClosedJsonSchema::boolean(false),
        )?]
    } else {
        outputs
            .iter()
            .map(|(name, output)| field(name, true, relay_output_schema(output)?))
            .collect::<Result<Vec<_>, RelayClientError>>()?
    };
    let outputs_schema = object(true, output_fields)?;
    let mut provenance_fields = vec![
        field("acquired_at", true, string(false, 64)?)?,
        field("source_observed_at", true, string(true, 64)?)?,
        field("source_revision", true, string(true, 128)?)?,
        field("acquisition_class", true, string(false, 32)?)?,
        field(
            "integration",
            true,
            object(
                false,
                vec![
                    field("id", true, string(false, PROFILE_ID_MAX_BYTES as u32)?)?,
                    field(
                        "revision",
                        true,
                        ClosedJsonSchema::integer(false, 1, MAX_JSON_INTEROPERABLE_INTEGER as i64)
                            .map_err(|_| RelayClientError::InvalidConfiguration)?,
                    )?,
                ],
            )?,
        )?,
        field(
            "consent",
            true,
            object(
                false,
                vec![
                    field("outcome", true, string(false, 32)?)?,
                    field("verifier_id", true, string(true, 128)?)?,
                    field("verifier_revision", true, string(true, 128)?)?,
                    field("checked_at", true, string(true, 64)?)?,
                    field("expires_at", true, string(true, 64)?)?,
                    field("revocation_status", true, string(false, 32)?)?,
                ],
            )?,
        )?,
    ];
    provenance_fields.push(field(
        "snapshot",
        false,
        object(
            false,
            vec![
                field("generation_id", true, string(true, 128)?)?,
                field("published_at", true, string(true, 64)?)?,
            ],
        )?,
    )?);
    let provenance = object(false, provenance_fields)?;
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
                        field("contract_hash", true, string(false, HASH_BYTES as u32)?)?,
                    ],
                )?,
            )?,
            field("outcome", true, string(false, 16)?)?,
            field("outputs", false, outputs_schema)?,
            field("provenance", true, provenance)?,
        ],
    )?;
    let mut projections = vec![
        projection("r00", &["schema"])?,
        projection("r01", &["consultation_id"])?,
        projection("r02", &["notary_evaluation_id"])?,
        projection("r03", &["profile", "id"])?,
        projection("r05", &["profile", "contract_hash"])?,
        projection("r06", &["outcome"])?,
        projection("r07", &["provenance", "acquired_at"])?,
        projection("r08", &["provenance", "source_observed_at"])?,
        projection("r09", &["provenance", "source_revision"])?,
        projection("r10", &["provenance", "acquisition_class"])?,
        projection("r11", &["provenance", "integration", "id"])?,
        projection("r12", &["provenance", "integration", "revision"])?,
        projection("r16", &["provenance", "consent", "outcome"])?,
        projection("r17", &["provenance", "consent", "verifier_id"])?,
        projection("r18", &["provenance", "consent", "verifier_revision"])?,
        projection("r19", &["provenance", "consent", "checked_at"])?,
        projection("r20", &["provenance", "consent", "expires_at"])?,
        projection("r21", &["provenance", "consent", "revocation_status"])?,
        projection("r22", &["provenance", "snapshot", "generation_id"])?,
        projection("r23", &["provenance", "snapshot", "published_at"])?,
    ];
    let mut presence = Vec::new();
    let output_projection_offset = 24;
    let VerifiedRelayResult::OutputMap(outputs) = &profile.result;
    for (index, name) in outputs.keys().enumerate() {
        projections.push(projection(
            &format!("r{:02}", output_projection_offset + index),
            &["outputs", name],
        )?);
    }
    presence.push(
        ClosedJsonPresenceProjection::new(
            &format!("r{:02}", output_projection_offset + outputs.len()),
            ["outputs"],
        )
        .map_err(|_| RelayClientError::InvalidConfiguration)?,
    );
    presence.push(
        ClosedJsonPresenceProjection::new("z00", ["provenance", "snapshot"])
            .map_err(|_| RelayClientError::InvalidConfiguration)?,
    );
    ClosedJsonDecoder::new_with_presence(
        schema,
        ClosedJsonRecordRoot::Object,
        projections,
        presence,
    )
    .map_err(|_| RelayClientError::InvalidConfiguration)
}

fn relay_output_schema(
    output: &NotaryRelayOutputContract,
) -> Result<ClosedJsonSchema, RelayClientError> {
    match output {
        NotaryRelayOutputContract::Boolean { .. } => Ok(ClosedJsonSchema::boolean(true)),
        NotaryRelayOutputContract::Integer {
            minimum, maximum, ..
        } => ClosedJsonSchema::integer(true, *minimum, *maximum)
            .map_err(|_| RelayClientError::InvalidConfiguration),
        NotaryRelayOutputContract::String { max_bytes, .. } => string(true, *max_bytes),
        NotaryRelayOutputContract::Date { .. } => string(true, 10),
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
    fields.require_string(profile.pin.contract_hash())?;
    let outcome = match fields.string()?.as_str() {
        "match" => RelayConsultationOutcome::Match,
        "no_match" => RelayConsultationOutcome::NoMatch,
        "ambiguous" => RelayConsultationOutcome::Ambiguous,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let acquired_at_text = fields.string()?;
    let acquired_at = OffsetDateTime::parse(&acquired_at_text, &Rfc3339)
        .map_err(|_| RelayClientError::InvalidResult)?;
    if acquired_at.unix_timestamp_nanos() <= 0 {
        return Err(RelayClientError::InvalidResult);
    }
    let source_observed_at = match fields.scalar()? {
        ProjectedJsonScalar::String(value) => {
            let observed_at = OffsetDateTime::parse(&value, &Rfc3339)
                .map_err(|_| RelayClientError::InvalidResult)?;
            if observed_at.unix_timestamp_nanos() <= 0 || observed_at > acquired_at {
                return Err(RelayClientError::InvalidResult);
            }
            Some(observed_at)
        }
        ProjectedJsonScalar::Null => None,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let source_revision_present = match fields.scalar()? {
        ProjectedJsonScalar::String(value) => {
            if value.is_empty() || value.len() > 128 {
                return Err(RelayClientError::InvalidResult);
            }
            true
        }
        ProjectedJsonScalar::Null => false,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let acquisition_class = match fields.string()?.as_str() {
        "source_projected_exact" => RelayAcquisitionClass::SourceProjectedExact,
        "bounded_full_record" => RelayAcquisitionClass::BoundedFullRecord,
        "materialized_snapshot" => RelayAcquisitionClass::MaterializedSnapshot,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let integration_id = fields.string()?;
    let integration_revision = fields.integer()?;
    if integration_id.as_str() != profile.semantics.integration_id.as_ref()
        || integration_revision != profile.semantics.integration_revision
    {
        return Err(RelayClientError::InvalidResult);
    }
    fields.require_string("not_required")?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_null()?;
    fields.require_string("not_applicable")?;
    let snapshot = match (fields.scalar()?, fields.scalar()?) {
        (ProjectedJsonScalar::String(generation_id), ProjectedJsonScalar::String(published_at)) => {
            if generation_id.is_empty() {
                return Err(RelayClientError::InvalidResult);
            }
            let published_at = OffsetDateTime::parse(&published_at, &Rfc3339)
                .map_err(|_| RelayClientError::InvalidResult)?;
            if published_at.unix_timestamp_nanos() <= 0 || published_at > acquired_at {
                return Err(RelayClientError::InvalidResult);
            }
            Some(())
        }
        (ProjectedJsonScalar::Null, ProjectedJsonScalar::Null) => None,
        _ => return Err(RelayClientError::InvalidResult),
    };
    let VerifiedRelayResult::OutputMap(outputs) = &profile.result;
    let projected = outputs
        .iter()
        .map(|(name, output)| {
            let value = fields.scalar()?;
            let valid = if outcome == RelayConsultationOutcome::Match {
                relay_output_value_valid(output, &value)
            } else {
                matches!(value, ProjectedJsonScalar::Null)
            };
            if !valid {
                return Err(RelayClientError::InvalidResult);
            }
            Ok((name.clone().into_boxed_str(), value))
        })
        .collect::<Result<BTreeMap<_, _>, RelayClientError>>()?;
    let outputs_present = fields.boolean()?;
    let match_data = match (outcome, outputs_present) {
        (RelayConsultationOutcome::Match, true) => {
            Some(RelayMatchData::OutputMap(RelayOutputMap {
                fields: projected,
            }))
        }
        (RelayConsultationOutcome::NoMatch | RelayConsultationOutcome::Ambiguous, false)
            if projected
                .values()
                .all(|value| matches!(value, ProjectedJsonScalar::Null)) =>
        {
            None
        }
        _ => return Err(RelayClientError::InvalidResult),
    };
    let snapshot_present = fields.boolean()?;
    match (acquisition_class, snapshot_present, snapshot.is_some()) {
        (RelayAcquisitionClass::MaterializedSnapshot, true, true)
        | (
            RelayAcquisitionClass::SourceProjectedExact | RelayAcquisitionClass::BoundedFullRecord,
            false,
            false,
        ) => {}
        _ => return Err(RelayClientError::InvalidResult),
    }
    let expected_acquisition = match profile.semantics.acquisition_class {
        VerifiedAcquisitionClass::SourceProjectedExact => {
            RelayAcquisitionClass::SourceProjectedExact
        }
        VerifiedAcquisitionClass::BoundedFullRecord => RelayAcquisitionClass::BoundedFullRecord,
        VerifiedAcquisitionClass::MaterializedSnapshot => {
            RelayAcquisitionClass::MaterializedSnapshot
        }
    };
    if acquisition_class != expected_acquisition
        || !source_field_matches(
            &profile.semantics.source_observed_at,
            source_observed_at.is_some(),
        )
        || !source_field_matches(&profile.semantics.source_revision, source_revision_present)
    {
        return Err(RelayClientError::InvalidResult);
    }
    if !fields.exhausted() {
        return Err(RelayClientError::InvalidResult);
    }

    Ok(RelayConsultationResult {
        consultation_id,
        outcome,
        match_data,
        provenance: RelayConsultationProvenance { acquired_at },
    })
}

fn source_field_matches(expected: &VerifiedSourceField, present: bool) -> bool {
    matches!(
        (expected, present),
        (VerifiedSourceField::Absent, false) | (VerifiedSourceField::Required, true)
    )
}

fn relay_output_value_valid(
    output: &NotaryRelayOutputContract,
    value: &ProjectedJsonScalar,
) -> bool {
    match (output, value) {
        (NotaryRelayOutputContract::Boolean { .. }, ProjectedJsonScalar::Boolean(_))
        | (NotaryRelayOutputContract::Integer { .. }, ProjectedJsonScalar::Integer(_))
        | (NotaryRelayOutputContract::String { .. }, ProjectedJsonScalar::String(_)) => true,
        (NotaryRelayOutputContract::Date { .. }, ProjectedJsonScalar::String(value)) => {
            is_rfc3339_full_date(value)
        }
        (output, ProjectedJsonScalar::Null) => output.nullable(),
        _ => false,
    }
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
        let (_, value) = self
            .fields
            .next()
            .map(ProjectedJsonField::into_parts)
            .ok_or(self.error)?;
        Ok(value)
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

    fn integer(&mut self) -> Result<i64, RelayClientError> {
        match self.scalar()? {
            ProjectedJsonScalar::Integer(value) => Ok(value),
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

    fn exhausted(&self) -> bool {
        self.fields.as_slice().is_empty()
    }
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
        StatusCode::CONFLICT => Err(RelayClientError::ContractMismatch),
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

fn output_name(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
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

fn canonical_ulid(value: &str) -> bool {
    Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}

#[cfg(test)]
mod tests;
