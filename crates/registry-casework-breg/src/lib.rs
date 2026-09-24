// SPDX-License-Identifier: Apache-2.0
//! BReg protocol stays at this internal adapter boundary. Events invalidate;
//! only a maintained-client read supplies the current source observation.

mod config;
pub use config::*;

use async_trait::async_trait;
use registry_breg_client::*;
use registry_casework_core::*;
use registry_platform_crypto::delivery_signature::{
    verify_v1, SignatureFields, MIN_HMAC_SHA256_KEY_BYTES,
};
use registry_platform_crypto::domain_separated_sha256;
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

/// One imported request entry. This does not grant source access.
#[derive(Clone, Debug)]
pub struct BregRequestConfig {
    pub entity: String,
    pub route: String,
    pub routing_metadata: RoutingSourceMetadata,
    /// Imported source descriptors for the exact fields a current human read
    /// may disclose through the unified review-task context endpoint.
    pub context_projection: Vec<RoutingFieldDescriptor>,
    pub display_reference: Option<RoutingFieldDescriptor>,
}

/// The imported request entries of one source and the single reader binding
/// they share. This does not grant source access.
#[derive(Clone, Debug)]
pub struct BregSourceConfig {
    pub source_id: String,
    pub requests: Vec<BregRequestConfig>,
    pub binding_generation: String,
    pub expected_registry_revision: String,
    pub reader_profile: String,
    pub event_source: String,
    pub event_type: String,
}

/// Where discovery resumes: the request entity whose listing is being read
/// and, inside that listing, the BReg continuation. A missing continuation
/// starts the named entity's listing from its first page.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DiscoveryPosition {
    entity: String,
    continuation: Option<BRegContinuationProjection>,
}

pub struct BregAdapter {
    config: BregSourceConfig,
    reader: BaseRegistryClient,
    webhook_key: Zeroizing<Vec<u8>>,
    /// The source reader failure cause last logged, so a persistent failure is
    /// reported once per change instead of once per subject read.
    reader_failure: Mutex<Option<String>>,
}

/// The credential behind a BReg read. A source reader failure stops Casework
/// learning about source changes, so its cause is logged. A caller's failure
/// is that caller's own refusal and is only returned.
#[derive(Clone, Copy)]
enum ReadClient<'a> {
    SourceReader,
    Caller(&'a BaseRegistryClient),
}

impl BregAdapter {
    pub fn new(
        config: BregSourceConfig,
        reader: BaseRegistryClient,
        webhook_key: Vec<u8>,
    ) -> Result<Self, SourceAdapterError> {
        if [
            &config.binding_generation,
            &config.expected_registry_revision,
            &config.reader_profile,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 512)
            || webhook_key.len() < MIN_HMAC_SHA256_KEY_BYTES
            || config.requests.is_empty()
            || config.requests.len() > MAXIMUM_REQUEST_ENTITIES
            || config
                .requests
                .iter()
                .any(|request| !valid_request_config(request))
            || config.requests.iter().enumerate().any(|(index, request)| {
                config.requests[..index]
                    .iter()
                    .any(|prior| prior.entity == request.entity || prior.route == request.route)
            })
        {
            return Err(SourceAdapterError::Invalid);
        }
        if !valid_source_identifier(&config.source_id)
            || !config
                .event_source
                .starts_with("urn:registrystack:registry:")
            || config.event_source.len() > 512
            || config.event_type.is_empty()
            || config.event_type.len() > 512
        {
            return Err(SourceAdapterError::Invalid);
        }
        Ok(Self {
            config,
            reader,
            webhook_key: Zeroizing::new(webhook_key),
            reader_failure: Mutex::new(None),
        })
    }

    /// Verify the configured BReg runtime and the complete read contract
    /// Casework needs without requiring a specimen request to exist.
    ///
    /// This proves only the caller-filtered reader surface. BReg's readiness
    /// response does not disclose its event destination, and this method must
    /// therefore not be used as evidence of end-to-end webhook delivery.
    pub async fn verify_reader_readiness(&self) -> Result<(), SourceAdapterError> {
        let ready = self.reader.ready().await;
        self.read_result(ReadClient::SourceReader, ready)?;
        let metadata = self
            .metadata(ReadClient::SourceReader, &self.config.reader_profile)
            .await?;
        for entry in &self.config.requests {
            self.verify_reader_operation(
                &metadata,
                entry,
                BRegOperationKind::Get,
                &format!("/v1/records/{}/{{record_id}}", entry.route),
            )?;
            self.verify_reader_operation(
                &metadata,
                entry,
                BRegOperationKind::List,
                &format!("/v1/records/{}", entry.route),
            )?;
        }

        for entry in &self.config.requests {
            let request = BRegListRequest::default()
                .options(Self::options(&self.config.reader_profile)?)
                .top(1)
                .map_err(|_| SourceAdapterError::Invalid)?
                .filter("bregState eq 'submitted'")
                .map_err(|_| SourceAdapterError::Invalid)?;
            let listed = self.reader.list_records(&entry.route, &request).await;
            self.read_result(ReadClient::SourceReader, listed)?;
        }
        Ok(())
    }

    fn verify_reader_operation(
        &self,
        metadata: &BRegMetadata,
        entry: &BregRequestConfig,
        kind: BRegOperationKind,
        expected_path: &str,
    ) -> Result<(), SourceAdapterError> {
        let identifier = format!("records.{}.{}", entry.entity, kind.as_str());
        let operation = metadata
            .operation(&identifier)
            .ok_or(SourceAdapterError::Denied)?;
        let required_fields = entry
            .routing_metadata
            .fields
            .iter()
            .map(|field| field.field.as_str())
            .chain(
                entry
                    .display_reference
                    .iter()
                    .map(|field| field.field.as_str()),
            )
            .collect::<Vec<_>>();
        if operation.kind() != &kind
            || operation.method() != "GET"
            || operation.path() != expected_path
            || operation.source_entity() != entry.entity
            || operation.response_entity() != entry.entity
            || operation.access_profile() != self.config.reader_profile
            || !operation.required_capabilities().is_empty()
            || required_fields.iter().any(|required| {
                !operation
                    .readable_fields()
                    .iter()
                    .any(|readable| readable == required)
            })
            // The adapter derives application eligibility and recovery state
            // from the caller-filtered request projection. A reader whose
            // grant conceals that projection cannot run the adapter.
            || !operation
                .readable_request_fields()
                .iter()
                .any(|field| field == "review_state")
        {
            return Err(SourceAdapterError::Denied);
        }
        Ok(())
    }

    /// The configured request entry a subject belongs to.
    fn request_entry(&self, entity: &str) -> Result<&BregRequestConfig, SourceAdapterError> {
        self.config
            .requests
            .iter()
            .find(|entry| entry.entity == entity)
            .ok_or(SourceAdapterError::Invalid)
    }

    fn validate_subject(
        &self,
        subject: &SubjectRef,
    ) -> Result<&BregRequestConfig, SourceAdapterError> {
        if subject.source_id != self.config.source_id || uuid::Uuid::parse_str(&subject.id).is_err()
        {
            return Err(SourceAdapterError::Invalid);
        }
        self.request_entry(&subject.kind)
    }

    fn caller(
        &self,
        credential: EphemeralCredential<'_>,
    ) -> Result<BaseRegistryClient, SourceAdapterError> {
        let token =
            BearerToken::new(credential.expose()).map_err(|_| SourceAdapterError::Denied)?;
        Ok(self.reader.with_bearer_token(token))
    }

    fn options(profile: &str) -> Result<BRegRecordOptions, SourceAdapterError> {
        BRegRecordOptions::default()
            .access_profile(profile)
            .map_err(|_| SourceAdapterError::Invalid)
    }

    fn client<'a>(&'a self, client: ReadClient<'a>) -> &'a BaseRegistryClient {
        match client {
            ReadClient::SourceReader => &self.reader,
            ReadClient::Caller(client) => client,
        }
    }

    /// Map a BReg read result. A source reader failure is logged when its
    /// cause first appears or changes, and the next success logs recovery.
    fn read_result<T>(
        &self,
        client: ReadClient<'_>,
        result: Result<T, BaseRegistryClientError>,
    ) -> Result<T, SourceAdapterError> {
        if let ReadClient::Caller(_) = client {
            return result.map_err(read_error);
        }
        let mut reported = self
            .reader_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(value) => {
                if reported.take().is_some() {
                    tracing::info!(
                        source_id = %self.config.source_id,
                        "Casework source reader requests to BReg succeed again"
                    );
                }
                Ok(value)
            }
            Err(error) => {
                let cause = error.to_string();
                // Metadata decode failures of different kinds render the same
                // message, so the kind is part of what counts as a change.
                let key = match error.metadata_error_kind() {
                    Some(kind) => format!("{cause} ({kind:?})"),
                    None => cause.clone(),
                };
                if reported.as_deref() != Some(key.as_str()) {
                    // A runtime metadata decode failure only ever comes from
                    // the GET /v1/registry contract read, so the route is
                    // named here rather than threaded through every caller.
                    match error.metadata_error_kind() {
                        Some(kind) => tracing::warn!(
                            source_id = %self.config.source_id,
                            route = "GET /v1/registry",
                            metadata_error_kind = ?kind,
                            error = %cause,
                            "Casework source reader request to BReg failed"
                        ),
                        None => tracing::warn!(
                            source_id = %self.config.source_id,
                            error = %cause,
                            "Casework source reader request to BReg failed"
                        ),
                    }
                    *reported = Some(key);
                }
                Err(read_error(error))
            }
        }
    }

    async fn metadata(
        &self,
        client: ReadClient<'_>,
        profile: &str,
    ) -> Result<BRegMetadata, SourceAdapterError> {
        let contract = self.client(client).registry_contract(Some(profile)).await;
        let metadata = self.read_result(client, contract)?.value;
        if metadata.registry_revision() != self.config.expected_registry_revision {
            return Err(SourceAdapterError::BindingMoved);
        }
        Ok(metadata)
    }

    async fn read(
        &self,
        client: ReadClient<'_>,
        subject: &SubjectRef,
        profile: &str,
    ) -> Result<(RegistryRecordSingleResponse, BRegMetadata, String), SourceAdapterError> {
        let entry = self.validate_subject(subject)?;
        let record = self
            .client(client)
            .get_record(&entry.route, &subject.id, &Self::options(profile)?)
            .await;
        // A missing record is an ordinary source state, not a reader failure.
        // A 404 from the registry contract, readiness, or a list still is.
        let response = match record {
            Err(error) if error.status() == Some(404) => return Err(read_error(error)),
            record => self.read_result(client, record)?,
        };
        let representation_etag = response
            .metadata
            .etag()
            .ok_or(SourceAdapterError::Invalid)?
            .as_str()
            .to_owned();
        let record = response.value;
        if record.meta.entity_type_identifier != entry.entity {
            return Err(SourceAdapterError::BindingMoved);
        }
        let metadata = self.metadata(client, profile).await?;
        Ok((record, metadata, representation_etag))
    }

    fn binding(
        &self,
        record: &RegistryRecordSingleResponse,
        request: &BRegRequestMetadata,
    ) -> Result<SourceBinding, SourceAdapterError> {
        ordered_revision(&record.data.revision_identifier)?;
        Ok(SourceBinding {
            source_revision: record.data.revision_identifier.clone(),
            version: request.proposal_version().get().to_string(),
            integrity: request.effect_digest().map(|d| d.as_str().to_owned()),
            generation: self.config.binding_generation.clone(),
        })
    }

    fn request(
        record: &RegistryRecordSingleResponse,
    ) -> Result<BRegRequestMetadata, SourceAdapterError> {
        BRegRequestMetadata::from_record(&record.data)
            .map_err(|_| SourceAdapterError::Invalid)?
            .ok_or(SourceAdapterError::Invalid)
    }

    fn subject(&self, entry: &BregRequestConfig, id: String) -> SubjectRef {
        SubjectRef {
            source_id: self.config.source_id.clone(),
            kind: entry.entity.clone(),
            id,
        }
    }

    fn occurrence_state(
        request: &BRegRequestMetadata,
    ) -> Result<OccurrenceState, SourceAdapterError> {
        match request.breg_state() {
            BRegRequestState::Draft => Ok(OccurrenceState::Superseded),
            BRegRequestState::Cancelled => Ok(OccurrenceState::Cancelled),
            BRegRequestState::Applied => Ok(OccurrenceState::Completed),
            BRegRequestState::Submitted => match request
                .review()
                .map(|review| review.application().state())
            {
                Some(BRegExternalReviewApplicationState::AwaitingReview)
                | Some(BRegExternalReviewApplicationState::Blocked)
                | Some(BRegExternalReviewApplicationState::Expired) => {
                    Ok(OccurrenceState::WaitingApplication)
                }
                Some(BRegExternalReviewApplicationState::Ready) => Ok(OccurrenceState::Open),
                Some(BRegExternalReviewApplicationState::Queued)
                | Some(BRegExternalReviewApplicationState::Applying) => {
                    Ok(OccurrenceState::Synchronizing)
                }
                Some(BRegExternalReviewApplicationState::Applied) => Ok(OccurrenceState::Completed),
                None if request
                    .advertised_operations()
                    .any(|operation| operation == BRegLifecycleOperation::ApplyRequest) =>
                {
                    Ok(OccurrenceState::Open)
                }
                None => Ok(OccurrenceState::WaitingApplication),
            },
        }
    }

    fn routing_context(
        entry: &BregRequestConfig,
        record: &RegistryRecordSingleResponse,
        kind: OccurrenceKind,
        state: OccurrenceState,
        stage: Option<&str>,
    ) -> Result<Option<RoutingContext>, SourceAdapterError> {
        if !state.is_active() {
            return Ok(None);
        }
        let activity = match kind {
            OccurrenceKind::Review => RoutingActivity::Review,
            OccurrenceKind::Application => RoutingActivity::Apply,
        };
        let fields = entry
            .routing_metadata
            .fields
            .iter()
            .filter_map(|descriptor| {
                record
                    .data
                    .domain_data
                    .get(&descriptor.api_name)
                    .cloned()
                    .map(|value| (descriptor.field.clone(), value))
            })
            .collect();
        Ok(Some(RoutingContext {
            activity,
            stage: stage.map(str::to_owned),
            fields,
        }))
    }

    fn display_reference(
        entry: &BregRequestConfig,
        record: &RegistryRecordSingleResponse,
    ) -> Result<Option<String>, SourceAdapterError> {
        let Some(field) = &entry.display_reference else {
            return Ok(None);
        };
        match record.data.domain_data.get(&field.api_name) {
            Some(Value::String(value))
                if !value.is_empty()
                    && value.chars().count() <= 512
                    && !value.chars().any(char::is_control) =>
            {
                Ok(Some(value.to_owned()))
            }
            None | Some(Value::Null) => Ok(None),
            _ => Err(SourceAdapterError::Invalid),
        }
    }
}

/// The most request entities one source may pair. Discovery walks every
/// entity's listing, so the bound keeps one reconciliation pass finite.
pub const MAXIMUM_REQUEST_ENTITIES: usize = 32;

fn valid_request_config(request: &BregRequestConfig) -> bool {
    !([&request.entity, &request.route]
        .iter()
        .any(|v| v.is_empty() || v.len() > 512)
        || !request.routing_metadata.stages.is_empty()
        || request.routing_metadata.fields.iter().any(|field| {
            field.field.is_empty()
                || field.field.len() > 512
                || field.api_name.is_empty()
                || field.api_name.len() > 512
                || !matches!(&field.schema, Value::Object(_) | Value::Bool(_))
        })
        || request
            .routing_metadata
            .fields
            .iter()
            .enumerate()
            .any(|(index, field)| {
                request.routing_metadata.fields[..index]
                    .iter()
                    .any(|prior| prior.field == field.field || prior.api_name == field.api_name)
            })
        || request.context_projection.len() > 32
        || request.context_projection.iter().any(|field| {
            field.field.is_empty()
                || field.field.len() > 128
                || field.api_name.is_empty()
                || field.api_name.len() > 128
                || !matches!(&field.schema, Value::Object(_) | Value::Bool(_))
                || !check_source_field_descriptor(field)
        })
        || request
            .context_projection
            .iter()
            .enumerate()
            .any(|(index, field)| {
                request.context_projection[..index]
                    .iter()
                    .any(|prior| prior.field == field.field || prior.api_name == field.api_name)
            })
        || request.display_reference.as_ref().is_some_and(|field| {
            field.field.is_empty()
                || field.api_name.is_empty()
                || field.field.len() > 512
                || field.api_name.len() > 512
                || field.schema.get("type").and_then(Value::as_str) != Some("string")
        }))
}

fn valid_source_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// BReg record revisions are canonical positive int64 decimals. This ordering
/// never applies to an arbitrary Registry Record identifier or an action ETag.
pub fn ordered_revision(value: &str) -> Result<i64, SourceAdapterError> {
    let revision: i64 = value.parse().map_err(|_| SourceAdapterError::Invalid)?;
    if revision <= 0 || revision.to_string() != value {
        return Err(SourceAdapterError::Invalid);
    }
    Ok(revision)
}

fn read_error(error: BaseRegistryClientError) -> SourceAdapterError {
    match error.status() {
        Some(401 | 403 | 404) => SourceAdapterError::Concealed,
        Some(409 | 412) => SourceAdapterError::BindingMoved,
        Some(400 | 422) => SourceAdapterError::Invalid,
        _ => SourceAdapterError::Unavailable,
    }
}

fn initial_refusal(
    status: u16,
    code: BRegProblemCode,
    execution: PreparedExecution,
) -> Option<SourceAdapterError> {
    if execution != PreparedExecution::Initial {
        return None;
    }
    if code == BRegProblemCode::IdempotencyConflict {
        return Some(SourceAdapterError::RequestRejected);
    }
    Some(match status {
        400 | 422 => SourceAdapterError::RequestRejected,
        404 => SourceAdapterError::RecordMissing,
        401 | 403 => SourceAdapterError::ReviewerNotAuthorized,
        409 | 412 => SourceAdapterError::ActionNotOffered,
        _ => return None,
    })
}

fn source_operation(
    operation: &OperationName,
) -> Result<BRegLifecycleOperation, SourceAdapterError> {
    match operation.as_str() {
        "submit" => Ok(BRegLifecycleOperation::SubmitRequest),
        "revise" => Ok(BRegLifecycleOperation::ReviseRequest),
        "cancel" => Ok(BRegLifecycleOperation::CancelRequest),
        "apply" => Ok(BRegLifecycleOperation::ApplyRequest),
        _ => Err(SourceAdapterError::Denied),
    }
}
fn operation(operation: BRegLifecycleOperation) -> Option<OperationName> {
    match operation {
        BRegLifecycleOperation::SubmitRequest => OperationName::parse("submit").ok(),
        BRegLifecycleOperation::ReviseRequest => OperationName::parse("revise").ok(),
        BRegLifecycleOperation::CancelRequest => OperationName::parse("cancel").ok(),
        BRegLifecycleOperation::ApplyRequest => OperationName::parse("apply").ok(),
    }
}

fn occurrence_key(
    kind: OccurrenceKind,
    stage: Option<&str>,
    binding: &SourceBinding,
) -> Result<String, SourceAdapterError> {
    let input = serde_json::to_vec(&(
        match kind {
            OccurrenceKind::Review => "review",
            OccurrenceKind::Application => "application",
        },
        stage,
        binding.version.as_str(),
        binding.generation.as_str(),
    ))
    .map_err(|_| SourceAdapterError::Invalid)?;
    let digest = domain_separated_sha256(b"registry-casework-breg-occurrence-v1\0", &input);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

/// Base Registry's record ETag covers the record revision but not the request
/// extension, so a review settlement leaves it unchanged. The observed
/// representation also binds the lifecycle facts derived from that extension,
/// so a settlement at an unchanged revision is observed as a new representation.
fn observed_representation_etag(
    record_etag: &str,
    state: OccurrenceState,
    remaining_actions: &[OperationName],
) -> Result<String, SourceAdapterError> {
    let input = serde_json::to_vec(&(record_etag, state, remaining_actions))
        .map_err(|_| SourceAdapterError::Invalid)?;
    let digest = domain_separated_sha256(b"registry-casework-breg-representation-v1\0", &input);
    Ok(format!(
        "\"sha256:{}\"",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn state_name(state: BRegRequestState) -> &'static str {
    match state {
        BRegRequestState::Draft => "draft",
        BRegRequestState::Submitted => "submitted",
        BRegRequestState::Cancelled => "cancelled",
        BRegRequestState::Applied => "applied",
    }
}

const LEGACY_SAVED_ATTEMPT_VERSION: u32 = 0;
const CURRENT_SAVED_ATTEMPT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct SavedAttempt {
    /// Version 0 is the legacy shape, where this field was absent. Compatible
    /// additive fields retain version 1 so version-1 readers can ignore them;
    /// incompatible shape changes must increment the version and fail closed.
    #[serde(default)]
    version: u32,
    subject: SubjectRef,
    actor: IssuerPrincipal,
    casework_profile: String,
    source_profile: String,
    binding: SourceBinding,
    native: Vec<u8>,
}

fn encode_saved_attempt(saved: &SavedAttempt) -> Result<Vec<u8>, SourceAdapterError> {
    serde_json::to_vec(saved).map_err(|_| SourceAdapterError::Invalid)
}

fn decode_saved_attempt(bytes: &[u8]) -> Result<SavedAttempt, SourceAdapterError> {
    let saved: SavedAttempt =
        serde_json::from_slice(bytes).map_err(|_| SourceAdapterError::Invalid)?;
    if !matches!(
        saved.version,
        LEGACY_SAVED_ATTEMPT_VERSION | CURRENT_SAVED_ATTEMPT_VERSION
    ) {
        return Err(SourceAdapterError::Invalid);
    }
    Ok(saved)
}

#[async_trait]
impl SourceAdapter for BregAdapter {
    fn source_id(&self) -> &str {
        &self.config.source_id
    }
    fn binding_generation(&self) -> &str {
        &self.config.binding_generation
    }

    fn routing_metadata(&self, entity: &str) -> Option<&RoutingSourceMetadata> {
        self.request_entry(entity)
            .ok()
            .map(|entry| &entry.routing_metadata)
    }

    async fn verify_transition(
        &self,
        request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        let mut headers = BTreeMap::new();
        for (name, value) in &request.headers {
            if headers
                .insert(name.to_ascii_lowercase(), value.as_str())
                .is_some()
            {
                return Err(SourceAdapterError::Invalid);
            }
        }
        let h = |name: &str| {
            headers
                .get(name)
                .copied()
                .ok_or(SourceAdapterError::Invalid)
        };
        if h("ce-specversion")? != "1.0"
            || h("ce-source")? != self.config.event_source
            || h("ce-type")? != self.config.event_type
        {
            return Err(SourceAdapterError::Invalid);
        }
        let path = format!("/events/sources/{}", self.config.source_id);
        verify_v1(
            &self.webhook_key,
            SignatureFields {
                id: h("ce-id")?,
                source: h("ce-source")?,
                event_type: h("ce-type")?,
                time: h("ce-time")?,
                data_schema: h("ce-dataschema")?,
                generation: h("x-registry-event-generation")?,
                attempt: h("x-registry-delivery-attempt")?,
                delivery_time: h("x-registry-delivery-time")?,
                method: "POST",
                request_target: &path,
                content_type: h("content-type")?,
                idempotency_key: h("idempotency-key")?,
                body: &request.body,
            },
            h("x-registry-signature")?,
            SystemTime::now(),
            Duration::from_secs(300),
        )
        .map_err(|_| SourceAdapterError::Invalid)?;
        // The delivery body is one shared hook envelope. Its identity is read
        // back from the bytes and held against the signed attributes the
        // signature already covered, so a body and its headers can never
        // describe two different events.
        let envelope =
            HookEnvelope::from_canonical_bytes(&request.body, &EnvelopeLimits::default())
                .map_err(|_| SourceAdapterError::Invalid)?;
        // The signed header spells the event time as RFC 3339 while the
        // envelope member is the normalized UTC form, so the two are held
        // against each other as instants rather than as strings.
        let signed_time = OffsetDateTime::parse(h("ce-time")?, &Rfc3339)
            .map_err(|_| SourceAdapterError::Invalid)?;
        if envelope.id != h("ce-id")?
            || envelope.event_type != h("ce-type")?
            || envelope.source != h("ce-source")?
            || envelope.dataschema != h("ce-dataschema")?
            || envelope.time.unix_timestamp_nanos() != signed_time.unix_timestamp_nanos()
        {
            return Err(SourceAdapterError::Invalid);
        }
        let body = envelope.data;
        if body.get("trigger").and_then(Value::as_str) != Some("request_lifecycle") {
            return Err(SourceAdapterError::Invalid);
        }
        let entry = self.request_entry(
            body.get("entity")
                .and_then(Value::as_str)
                .ok_or(SourceAdapterError::Invalid)?,
        )?;
        let subject = self.subject(
            entry,
            body.get("recordId")
                .and_then(Value::as_str)
                .ok_or(SourceAdapterError::Invalid)?
                .to_owned(),
        );
        self.validate_subject(&subject)?;
        let revision = body
            .get("revision")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0)
            .ok_or(SourceAdapterError::Invalid)?;
        let dedup = body
            .pointer("/request/deduplicationKey")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .ok_or(SourceAdapterError::Invalid)?;
        // `values`, reason and all other payload content die with this request.
        Ok(TransitionHint {
            subject,
            ordered_revision: revision,
            deduplication_key: dedup.to_owned(),
        })
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        let (record, _, representation_etag) = self
            .read(
                ReadClient::SourceReader,
                subject,
                &self.config.reader_profile,
            )
            .await?;
        let entry = self.request_entry(&subject.kind)?;
        let request = Self::request(&record)?;
        let binding = self.binding(&record, &request)?;
        let kind = OccurrenceKind::Application;
        let state = Self::occurrence_state(&request)?;
        let routing_context = Self::routing_context(entry, &record, kind, state, None)?;
        let remaining_actions: Vec<OperationName> = request
            .advertised_operations()
            .filter_map(operation)
            .collect();
        let representation_etag =
            observed_representation_etag(&representation_etag, state, &remaining_actions)?;
        Ok(AuthoritativeObservation {
            subject: subject.clone(),
            occurrence_key: occurrence_key(kind, None, &binding)?,
            ordered_revision: ordered_revision(&record.data.revision_identifier)?,
            representation_etag,
            binding,
            display_reference: Self::display_reference(entry, &record)?,
            occurrence_kind: kind,
            stage: None,
            submitted_at: None,
            stage_entered_at: None,
            review_timing: None,
            routing_context,
            state,
            remaining_actions,
        })
    }

    async fn discover_active(
        &self,
        cursor: Option<&DiscoveryCursor>,
        limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        self.metadata(ReadClient::SourceReader, &self.config.reader_profile)
            .await?;
        let (mut index, mut continuation) = match cursor {
            Some(cursor) => {
                let position: DiscoveryPosition =
                    serde_json::from_str(&cursor.0).map_err(|_| SourceAdapterError::Invalid)?;
                let index = self
                    .config
                    .requests
                    .iter()
                    .position(|entry| entry.entity == position.entity)
                    .ok_or(SourceAdapterError::Invalid)?;
                let continuation = position
                    .continuation
                    .map(|projection| {
                        let continuation = BRegContinuation::try_from_projection(projection)
                            .map_err(|_| SourceAdapterError::Invalid)?;
                        if continuation.route() != self.config.requests[index].route
                            || continuation.access_profile()
                                != Some(self.config.reader_profile.as_str())
                        {
                            return Err(SourceAdapterError::Invalid);
                        }
                        Ok(continuation)
                    })
                    .transpose()?;
                (index, continuation)
            }
            None => (0, None),
        };
        loop {
            let entry = &self.config.requests[index];
            let page = match continuation.take() {
                Some(continuation) => self.reader.continue_list(&continuation).await,
                None => {
                    let request = BRegListRequest::default()
                        .options(Self::options(&self.config.reader_profile)?)
                        .top(
                            u32::try_from(limit.clamp(1, 100))
                                .map_err(|_| SourceAdapterError::Invalid)?,
                        )
                        .map_err(|_| SourceAdapterError::Invalid)?
                        .filter("bregState eq 'submitted'")
                        .map_err(|_| SourceAdapterError::Invalid)?;
                    self.reader.list_records(&entry.route, &request).await
                }
            };
            let page = self.read_result(ReadClient::SourceReader, page)?.value;
            let subjects = page
                .value
                .items
                .into_iter()
                .map(|r| {
                    let subject = self.subject(entry, r.record_identifier);
                    self.validate_subject(&subject)?;
                    Ok(subject)
                })
                .collect::<Result<Vec<_>, SourceAdapterError>>()?;
            let next = match page.continuation {
                Some(continuation) => Some(DiscoveryPosition {
                    entity: entry.entity.clone(),
                    continuation: Some(continuation.projection()),
                }),
                None => self
                    .config
                    .requests
                    .get(index + 1)
                    .map(|next| DiscoveryPosition {
                        entity: next.entity.clone(),
                        continuation: None,
                    }),
            };
            // An exhausted listing with nothing in it moves straight on, so a
            // caller probing with a small limit sees the next entity's work.
            if subjects.is_empty() {
                if let Some(DiscoveryPosition {
                    continuation: None, ..
                }) = next
                {
                    index += 1;
                    continue;
                }
            }
            let next_cursor = next
                .map(|position| serde_json::to_string(&position).map(DiscoveryCursor))
                .transpose()
                .map_err(|_| SourceAdapterError::Invalid)?;
            return Ok(ActiveSubjectsPage {
                subjects,
                next_cursor,
            });
        }
    }

    async fn read_task_context(
        &self,
        subject: &SubjectRef,
        fields: &[String],
        caller: Option<(&str, EphemeralCredential<'_>)>,
    ) -> Result<TaskSubjectContext, SourceAdapterError> {
        let entry = self.request_entry(&subject.kind)?;
        if fields.is_empty()
            || fields.len() > 32
            || fields.iter().any(|field| {
                !entry
                    .routing_metadata
                    .fields
                    .iter()
                    .any(|descriptor| descriptor.field == *field)
            })
        {
            return Err(SourceAdapterError::Denied);
        }
        let record = if let Some((profile, credential)) = caller {
            let client = self.caller(credential)?;
            self.read(ReadClient::Caller(&client), subject, profile)
                .await?
                .0
        } else {
            self.read(
                ReadClient::SourceReader,
                subject,
                &self.config.reader_profile,
            )
            .await?
            .0
        };
        let request = Self::request(&record)?;
        if matches!(
            request.breg_state(),
            BRegRequestState::Draft | BRegRequestState::Applied | BRegRequestState::Cancelled
        ) {
            return Err(SourceAdapterError::Denied);
        }
        let mut values = BTreeMap::new();
        for field in fields {
            let descriptor = entry
                .routing_metadata
                .fields
                .iter()
                .find(|descriptor| descriptor.field == *field)
                .ok_or(SourceAdapterError::Denied)?;
            let value = record
                .data
                .domain_data
                .get(&descriptor.api_name)
                .ok_or(SourceAdapterError::Denied)?;
            values.insert(field.clone(), value.clone());
        }
        Ok(TaskSubjectContext {
            binding: self.binding(&record, &request)?,
            values,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        profile: &str,
        credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        let caller = self.caller(credential)?;
        let (record, _, _) = self
            .read(ReadClient::Caller(&caller), subject, profile)
            .await?;
        let entry = self.request_entry(&subject.kind)?;
        let request = Self::request(&record)?;
        let mut disclosed = BTreeMap::new();
        for field in &entry.context_projection {
            let Some(value) = record.data.domain_data.get(&field.api_name) else {
                // Caller-filtered BReg reads omit fields this exact human and
                // profile cannot see. Omission must never be widened with the
                // source reader's service credential.
                continue;
            };
            if validate_source_field_value(field, value).is_err() {
                return Err(SourceAdapterError::Invalid);
            }
            disclosed.insert(field.api_name.clone(), value.clone());
        }
        if !serde_json::to_vec(&disclosed).is_ok_and(|bytes| bytes.len() <= 16 * 1024) {
            return Err(SourceAdapterError::Invalid);
        }
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: self.binding(&record, &request)?,
            display_reference: Self::display_reference(entry, &record)?,
            disclosed,
            permitted_operations: request
                .advertised_operations()
                .filter_map(operation)
                .collect(),
        })
    }

    async fn prepare_action(
        &self,
        input: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        if input.displayed_binding.generation != self.config.binding_generation {
            return Err(SourceAdapterError::BindingMoved);
        }
        let caller = self.caller(input.credential)?;
        let (record, metadata, _) = self
            .read(
                ReadClient::Caller(&caller),
                input.subject,
                input.source_profile_id,
            )
            .await?;
        let request = Self::request(&record)?;
        let binding = self.binding(&record, &request)?;
        if &binding != input.displayed_binding {
            return Err(SourceAdapterError::BindingMoved);
        }
        let authority = metadata
            .select_lifecycle(&input.subject.kind, input.source_profile_id)
            .map_err(|_| SourceAdapterError::Denied)?;
        let mut action = caller
            .lifecycle_actions(&authority, &record)
            .map_err(|_| SourceAdapterError::Invalid)?
            .into_iter()
            .find(|a| Ok(a.operation()) == source_operation(&input.operation))
            .ok_or(SourceAdapterError::Denied)?;
        if let Some(reason) = input.reason {
            action = action
                .with_reason(reason)
                .map_err(|_| SourceAdapterError::Invalid)?;
        }
        let key = BRegIdempotencyKey::parse(input.idempotency_key)
            .map_err(|_| SourceAdapterError::Invalid)?;
        let prepared = caller
            .prepare_lifecycle_action(&authority, &record, &action, &key)
            .map_err(|_| SourceAdapterError::Invalid)?;
        let saved = SavedAttempt {
            version: CURRENT_SAVED_ATTEMPT_VERSION,
            subject: input.subject.clone(),
            actor: input.actor.principal.clone(),
            casework_profile: input.actor.profile_id.clone(),
            source_profile: input.source_profile_id.to_owned(),
            binding: binding.clone(),
            native: prepared.as_bytes().to_vec(),
        };
        Ok(PreparedSourceAttempt {
            source_binding: binding,
            recovery_evidence: RecoveryEvidence::new(encode_saved_attempt(&saved)?)?,
        })
    }

    async fn execute_prepared(
        &self,
        input: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        let saved = decode_saved_attempt(input.prepared.recovery_evidence.as_bytes())?;
        self.validate_subject(&saved.subject)?;
        if saved.actor != input.actor.principal
            || saved.casework_profile != input.actor.profile_id
            || saved.source_profile != input.source_profile_id
        {
            return Err(SourceAdapterError::Denied);
        }
        if saved.binding != input.prepared.source_binding
            || saved.binding.generation != self.config.binding_generation
        {
            return Err(SourceAdapterError::BindingMoved);
        }
        let caller = self.caller(input.credential)?;
        let metadata = self
            .metadata(ReadClient::Caller(&caller), input.source_profile_id)
            .await
            .map_err(|error| {
                if error == SourceAdapterError::Unavailable {
                    SourceAdapterError::Uncertain
                } else {
                    error
                }
            })?;
        let authority = metadata
            .select_lifecycle(&saved.subject.kind, input.source_profile_id)
            .map_err(|_| SourceAdapterError::Denied)?;
        let native = BRegPreparedLifecycle::from_slice(&saved.native)
            .map_err(|_| SourceAdapterError::Invalid)?;
        let (action, key) = caller
            .recover_lifecycle_action(&authority, &native)
            .map_err(|_| SourceAdapterError::BindingMoved)?;
        if key.as_str() != input.idempotency_key {
            return Err(SourceAdapterError::Invalid);
        }
        let response = caller
            .execute_lifecycle_action(&action, &key)
            .await
            .map_err(|error| match error {
                // Only the maintained client's validated problem response from
                // the actual POST proves a refusal. A protocol failure carrying
                // a 4xx status is not equivalent evidence.
                BaseRegistryClientError::Problem { status, code, .. } => {
                    initial_refusal(status, code, input.execution)
                        .unwrap_or(SourceAdapterError::Uncertain)
                }
                _ => SourceAdapterError::Uncertain,
            })?;
        let receipt = &response.value;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "nativeReceipt".into(),
            serde_json::to_string(&receipt.to_value())
                .map_err(|_| SourceAdapterError::Uncertain)?,
        );
        metadata.insert("traceId".into(), response.metadata.trace_id().to_string());
        Ok(SourceReceipt {
            source_revision: receipt.revision().to_string(),
            resulting_state: state_name(receipt.request().breg_state()).into(),
            binding: SourceBinding {
                source_revision: receipt.revision().to_string(),
                version: receipt
                    .request()
                    .proposal_version()
                    .map(|v| v.get().to_string())
                    .unwrap_or_else(|| saved.binding.version.clone()),
                integrity: receipt
                    .request()
                    .effect_digest()
                    .map(|d| d.as_str().to_owned()),
                generation: self.config.binding_generation.clone(),
            },
            actor_reference: receipt.actor_reference().map(str::to_owned),
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved_attempt(version: u32) -> SavedAttempt {
        SavedAttempt {
            version,
            subject: SubjectRef {
                source_id: "source".into(),
                kind: "company".into(),
                id: "company-1".into(),
            },
            actor: IssuerPrincipal {
                issuer: "https://idp.example".into(),
                subject: "alice".into(),
            },
            casework_profile: "staff".into(),
            source_profile: "reviewer".into(),
            binding: SourceBinding {
                source_revision: "7".into(),
                version: "proposal-1".into(),
                integrity: None,
                generation: "generation-1".into(),
            },
            native: vec![1, 2, 3],
        }
    }

    #[test]
    fn saved_attempt_current_version_round_trips_with_additive_fields() {
        let expected = saved_attempt(CURRENT_SAVED_ATTEMPT_VERSION);
        let encoded = encode_saved_attempt(&expected).expect("encode current saved attempt");
        let mut value: Value = serde_json::from_slice(&encoded).expect("saved attempt JSON");
        assert_eq!(value["version"], CURRENT_SAVED_ATTEMPT_VERSION);
        value.as_object_mut().expect("saved attempt object").insert(
            "future_optional_note".into(),
            Value::String("ignored".into()),
        );

        let decoded = decode_saved_attempt(
            &serde_json::to_vec(&value).expect("encode additive saved attempt"),
        )
        .expect("decode current saved attempt");
        assert_eq!(decoded.version, CURRENT_SAVED_ATTEMPT_VERSION);
        assert_eq!(decoded.subject, expected.subject);
        assert_eq!(decoded.actor, expected.actor);
        assert_eq!(decoded.casework_profile, expected.casework_profile);
        assert_eq!(decoded.source_profile, expected.source_profile);
        assert_eq!(decoded.binding, expected.binding);
        assert_eq!(decoded.native, expected.native);
    }

    #[test]
    fn revision_order_is_canonical_positive_int64_only() {
        for invalid in [
            "0",
            "-1",
            "+1",
            "01",
            "1.0",
            " 1",
            "9223372036854775808",
            "etag",
        ] {
            assert!(ordered_revision(invalid).is_err(), "{invalid}");
        }
        assert_eq!(ordered_revision("1"), Ok(1));
        assert_eq!(ordered_revision("9223372036854775807"), Ok(i64::MAX));
    }

    #[test]
    fn occurrence_identity_is_adapter_owned_and_binding_sensitive() {
        let binding = SourceBinding {
            source_revision: "1".into(),
            version: "proposal-1".into(),
            integrity: None,
            generation: "generation-1".into(),
        };
        let review = occurrence_key(OccurrenceKind::Review, Some("review"), &binding)
            .expect("review occurrence key");
        let mut changed = binding.clone();
        changed.version = "proposal-2".into();
        assert_ne!(
            review,
            occurrence_key(OccurrenceKind::Review, Some("review"), &changed)
                .expect("changed occurrence key")
        );
        assert_ne!(
            review,
            occurrence_key(OccurrenceKind::Application, None, &binding)
                .expect("application occurrence key")
        );
    }

    #[test]
    fn open_core_operation_names_do_not_expand_breg_authority() {
        let custom = OperationName::parse("verify_documents").expect("custom core operation");
        assert_eq!(source_operation(&custom), Err(SourceAdapterError::Denied));
    }

    #[test]
    fn initial_problem_statuses_preserve_each_refusal_class() {
        for (statuses, expected) in [
            (&[400, 422][..], SourceAdapterError::RequestRejected),
            (&[404][..], SourceAdapterError::RecordMissing),
            (&[401, 403][..], SourceAdapterError::ReviewerNotAuthorized),
            (&[409, 412][..], SourceAdapterError::ActionNotOffered),
        ] {
            for status in statuses {
                assert_eq!(
                    initial_refusal(
                        *status,
                        BRegProblemCode::MutationConflict,
                        PreparedExecution::Initial,
                    ),
                    Some(expected)
                );
                assert_eq!(
                    initial_refusal(
                        *status,
                        BRegProblemCode::MutationConflict,
                        PreparedExecution::Recovery,
                    ),
                    None
                );
            }
        }
        assert_eq!(
            initial_refusal(
                500,
                BRegProblemCode::ServiceUnavailable,
                PreparedExecution::Initial,
            ),
            None
        );
        assert_eq!(
            initial_refusal(
                409,
                BRegProblemCode::IdempotencyConflict,
                PreparedExecution::Initial,
            ),
            Some(SourceAdapterError::RequestRejected)
        );
        assert_eq!(
            initial_refusal(
                409,
                BRegProblemCode::IdempotencyConflict,
                PreparedExecution::Recovery,
            ),
            None
        );
    }
}
