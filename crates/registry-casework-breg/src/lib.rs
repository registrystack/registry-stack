// SPDX-License-Identifier: Apache-2.0
//! BReg protocol stays at this internal adapter boundary. Events invalidate;
//! only a maintained-client read supplies the current source observation.

mod config;
pub use config::*;

use async_trait::async_trait;
use registry_breg_client::*;
use registry_casework_core::*;
use registry_platform_crypto::breg_webhook::{
    verify_v1, SignatureFields, MIN_HMAC_SHA256_KEY_BYTES,
};
use registry_platform_crypto::domain_separated_sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

/// One imported, single-stage request entry. This does not grant source access.
#[derive(Clone, Debug)]
pub struct BregSourceConfig {
    pub source_id: String,
    pub entity: String,
    pub route: String,
    pub stage: String,
    pub binding_generation: String,
    pub expected_registry_revision: String,
    pub reader_profile: String,
    pub event_source: String,
    pub event_type: String,
}

pub struct BregAdapter {
    config: BregSourceConfig,
    reader: BaseRegistryClient,
    webhook_key: Zeroizing<Vec<u8>>,
}

impl BregAdapter {
    pub fn new(
        config: BregSourceConfig,
        reader: BaseRegistryClient,
        webhook_key: Vec<u8>,
    ) -> Result<Self, SourceAdapterError> {
        if [
            &config.source_id,
            &config.entity,
            &config.route,
            &config.stage,
            &config.binding_generation,
            &config.expected_registry_revision,
            &config.reader_profile,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 512)
            || webhook_key.len() < MIN_HMAC_SHA256_KEY_BYTES
        {
            return Err(SourceAdapterError::Invalid);
        }
        if !config
            .source_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
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
        })
    }

    fn validate_subject(&self, subject: &SubjectRef) -> Result<(), SourceAdapterError> {
        if subject.source_id != self.config.source_id
            || subject.kind != self.config.entity
            || uuid::Uuid::parse_str(&subject.id).is_err()
        {
            return Err(SourceAdapterError::Invalid);
        }
        Ok(())
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

    async fn metadata(
        &self,
        client: &BaseRegistryClient,
        profile: &str,
    ) -> Result<BRegMetadata, SourceAdapterError> {
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(read_error)?
            .value;
        if metadata.registry_revision() != self.config.expected_registry_revision {
            return Err(SourceAdapterError::BindingMoved);
        }
        Ok(metadata)
    }

    async fn read(
        &self,
        client: &BaseRegistryClient,
        subject: &SubjectRef,
        profile: &str,
    ) -> Result<(RegistryRecordSingleResponse, BRegMetadata, String), SourceAdapterError> {
        self.validate_subject(subject)?;
        let response = client
            .get_record(&self.config.route, &subject.id, &Self::options(profile)?)
            .await
            .map_err(read_error)?;
        let representation_etag = response
            .metadata
            .etag()
            .ok_or(SourceAdapterError::Invalid)?
            .as_str()
            .to_owned();
        let record = response.value;
        if record.meta.entity_type_identifier != self.config.entity {
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

    fn subject(&self, id: String) -> SubjectRef {
        SubjectRef {
            source_id: self.config.source_id.clone(),
            kind: self.config.entity.clone(),
            id,
        }
    }
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

fn source_operation(
    operation: &OperationName,
) -> Result<BRegLifecycleOperation, SourceAdapterError> {
    match operation.as_str() {
        "approve" => Ok(BRegLifecycleOperation::ApproveRequest),
        "reject" => Ok(BRegLifecycleOperation::RejectRequest),
        "request_correction" => Ok(BRegLifecycleOperation::RequestRevision),
        "apply" => Ok(BRegLifecycleOperation::ApplyRequest),
        _ => Err(SourceAdapterError::Denied),
    }
}
fn operation(operation: BRegLifecycleOperation) -> Option<OperationName> {
    match operation {
        BRegLifecycleOperation::ApproveRequest => OperationName::parse("approve").ok(),
        BRegLifecycleOperation::RejectRequest => OperationName::parse("reject").ok(),
        BRegLifecycleOperation::RequestRevision => OperationName::parse("request_correction").ok(),
        BRegLifecycleOperation::ApplyRequest => OperationName::parse("apply").ok(),
        _ => None,
    }
}

fn occurrence_key(
    kind: OccurrenceKind,
    stage: Option<&str>,
    binding: &SourceBinding,
) -> Result<String, SourceAdapterError> {
    let input = serde_json::to_vec(&(
        occurrence_kind_name(kind),
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

fn occurrence_kind_name(kind: OccurrenceKind) -> &'static str {
    match kind {
        OccurrenceKind::Review => "review",
        OccurrenceKind::Application => "application",
    }
}
fn state_name(state: BRegRequestState) -> &'static str {
    match state {
        BRegRequestState::Draft => "draft",
        BRegRequestState::Submitted => "submitted",
        BRegRequestState::Approved => "approved",
        BRegRequestState::NeedsChanges => "needs_changes",
        BRegRequestState::Rejected => "rejected",
        BRegRequestState::Canceled => "canceled",
        BRegRequestState::Applied => "applied",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAttempt {
    subject: SubjectRef,
    actor: IssuerPrincipal,
    casework_profile: String,
    source_profile: String,
    binding: SourceBinding,
    native: Vec<u8>,
}

#[async_trait]
impl SourceAdapter for BregAdapter {
    fn source_id(&self) -> &str {
        &self.config.source_id
    }
    fn binding_generation(&self) -> &str {
        &self.config.binding_generation
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
        let body = decode_exact_json(&request.body).map_err(|_| SourceAdapterError::Invalid)?;
        if body.get("trigger").and_then(Value::as_str) != Some("request_lifecycle")
            || body.get("entity").and_then(Value::as_str) != Some(self.config.entity.as_str())
        {
            return Err(SourceAdapterError::Invalid);
        }
        let subject = self.subject(
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
            .read(&self.reader, subject, &self.config.reader_profile)
            .await?;
        let request = Self::request(&record)?;
        let binding = self.binding(&record, &request)?;
        let (kind, state) = match request.breg_state() {
            BRegRequestState::Draft => (OccurrenceKind::Review, OccurrenceState::Superseded),
            BRegRequestState::Submitted => (OccurrenceKind::Review, OccurrenceState::Open),
            BRegRequestState::NeedsChanges => {
                (OccurrenceKind::Review, OccurrenceState::WaitingApplicant)
            }
            BRegRequestState::Approved => (OccurrenceKind::Application, OccurrenceState::Open),
            BRegRequestState::Rejected | BRegRequestState::Applied => {
                (OccurrenceKind::Review, OccurrenceState::Completed)
            }
            BRegRequestState::Canceled => (OccurrenceKind::Review, OccurrenceState::Cancelled),
        };
        Ok(AuthoritativeObservation {
            subject: subject.clone(),
            occurrence_key: occurrence_key(
                kind,
                (kind == OccurrenceKind::Review).then_some(self.config.stage.as_str()),
                &binding,
            )?,
            ordered_revision: ordered_revision(&record.data.revision_identifier)?,
            representation_etag,
            binding,
            occurrence_kind: kind,
            stage: (kind == OccurrenceKind::Review).then(|| self.config.stage.clone()),
            state,
            remaining_actions: vec![],
        })
    }

    async fn discover_active(
        &self,
        cursor: Option<&DiscoveryCursor>,
        limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        self.metadata(&self.reader, &self.config.reader_profile)
            .await?;
        let page = match cursor {
            Some(cursor) => {
                let projection: BRegContinuationProjection = serde_json::from_str(&cursor.0).map_err(|_| SourceAdapterError::Invalid)?;
                let continuation = BRegContinuation::try_from_projection(projection).map_err(|_| SourceAdapterError::Invalid)?;
                if continuation.route() != self.config.route || continuation.access_profile() != Some(self.config.reader_profile.as_str()) {
                    return Err(SourceAdapterError::Invalid);
                }
                self.reader.continue_list(&continuation).await
            }
            None => {
                let request = BRegListRequest::default().options(Self::options(&self.config.reader_profile)?)
                    .top(u32::try_from(limit.clamp(1,100)).map_err(|_| SourceAdapterError::Invalid)?).map_err(|_| SourceAdapterError::Invalid)?
                    .filter("bregState eq 'submitted' or bregState eq 'approved' or bregState eq 'needs_changes'").map_err(|_| SourceAdapterError::Invalid)?;
                self.reader.list_records(&self.config.route, &request).await
            }
        }.map_err(read_error)?.value;
        let subjects = page
            .value
            .items
            .into_iter()
            .map(|r| {
                let subject = self.subject(r.record_identifier);
                self.validate_subject(&subject)?;
                Ok(subject)
            })
            .collect::<Result<Vec<_>, SourceAdapterError>>()?;
        let next_cursor = page
            .continuation
            .map(|c| serde_json::to_string(&c.projection()).map(DiscoveryCursor))
            .transpose()
            .map_err(|_| SourceAdapterError::Invalid)?;
        Ok(ActiveSubjectsPage {
            subjects,
            next_cursor,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        profile: &str,
        credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        let caller = self.caller(credential)?;
        let (record, _, _) = self.read(&caller, subject, profile).await?;
        let request = Self::request(&record)?;
        let mut reasons: Vec<_> = request
            .decisions()
            .iter()
            .filter_map(|d| d.reason())
            .map(|s| Value::String(s.to_owned()))
            .collect();
        if let Some(proposals) = request
            .retained_history()
            .and_then(|h| h.get("proposals"))
            .and_then(Value::as_array)
        {
            for proposal in proposals {
                if let Some(decisions) = proposal.get("decisions").and_then(Value::as_array) {
                    reasons.extend(
                        decisions
                            .iter()
                            .filter_map(|d| d.get("reason"))
                            .filter(|v| v.is_string())
                            .cloned(),
                    );
                }
            }
        }
        let mut disclosed = BTreeMap::new();
        if !reasons.is_empty() {
            disclosed.insert("reasons".into(), Value::Array(reasons));
        }
        if !record.data.domain_data.is_empty() {
            // Names are used only to filter Casework's routing flags. Values
            // stay in the caller's direct BReg read and are never copied here.
            disclosed.insert(
                "readableFields".into(),
                Value::Array(
                    record
                        .data
                        .domain_data
                        .keys()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: self.binding(&record, &request)?,
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
            .read(&caller, input.subject, input.source_profile_id)
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
            subject: input.subject.clone(),
            actor: input.actor.principal.clone(),
            casework_profile: input.actor.profile_id.clone(),
            source_profile: input.source_profile_id.to_owned(),
            binding: binding.clone(),
            native: prepared.as_bytes().to_vec(),
        };
        Ok(PreparedSourceAttempt {
            source_binding: binding,
            recovery_evidence: RecoveryEvidence::new(
                serde_json::to_vec(&saved).map_err(|_| SourceAdapterError::Invalid)?,
            )?,
        })
    }

    async fn execute_prepared(
        &self,
        input: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        let saved: SavedAttempt =
            serde_json::from_slice(input.prepared.recovery_evidence.as_bytes())
                .map_err(|_| SourceAdapterError::Invalid)?;
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
            .metadata(&caller, input.source_profile_id)
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
                BaseRegistryClientError::Problem {
                    status: 400 | 401 | 403 | 404 | 409 | 412 | 422,
                    ..
                } if input.execution == PreparedExecution::Initial => {
                    SourceAdapterError::DefinitiveRefusal
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
            actor_reference: None,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
