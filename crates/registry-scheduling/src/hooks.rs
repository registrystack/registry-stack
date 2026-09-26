// SPDX-License-Identifier: Apache-2.0

//! Scheduling's closed after-commit appointment observer runtime.
//!
//! The shared hook crate owns the envelope and delivery state machine. This
//! module owns Scheduling's policy: three appointment lifecycle triggers,
//! caller-selected projections over a closed set of non-attributable claim
//! fields, URL handlers only, exact deployment destination activation, and a
//! worker that can observe an answer but can never apply a proposal.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use registry_platform_audit::AuditEntry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{ProtectedSecret, SecretResolver, MAX_SECRET_BYTES};
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use registry_platform_hooks::delivery::{
    insert_delivery, DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase,
    DeliveryAuditRecord, DeliveryCapture, DeliveryConfig, DeliveryConnection, DeliveryError,
    DeliveryOperationalEvent, DeliveryOutcome, DeliverySeams, DeliveryService,
    DeliverySignatureFields, DeliverySignatureRefused, DeliveryWorker, DestinationAnswer,
    HandlerRunFailure, HookDestination, HookHandler, HookHandlerBinding, ProposalApplication,
    ProposalOutcome, ProposalReceiptRecovery,
};
use registry_platform_hooks::{
    validate_hooks, BoundedText, Causation, EnvelopeLimits, EventSubject, HookDeclaration,
    HookEnvelope, HookHandlerKind, HookHandlerSource, HookPhase, MAX_OUTPUT_BYTES,
    MAX_REFUSAL_CODE_BYTES, MAX_REFUSAL_SUMMARY_BYTES,
};
use registry_platform_httputil::destination::{
    DestinationProfile, DestinationRequestError, DestinationResponseError, DestinationSendError,
    EventDeliveryHeaders, EventDestinationPolicy, EventDestinationRequest,
    EventDestinationRequestTemplate, MAX_DESTINATION_REQUEST_BODY_BYTES,
    MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use registry_scheduling_core::{
    valid_identifier, APPOINTMENT_CANCELLED_TRIGGER, APPOINTMENT_CONFIRMED_TRIGGER,
    APPOINTMENT_RESCHEDULED_TRIGGER,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_postgres::Transaction;
use url::Url;
use uuid::Uuid;

use crate::audit::{SchedulingAudit, SCHEDULING_AUDIT_SCHEMA};
use crate::config::HookDestinationConfig;
use crate::store::{ClaimRow, PostgresStore};

const DESTINATION_BINDING_SCHEMA: &str = "registry.scheduling-hook-destinations/v1";
const COMPILED_HOOK_SCHEMA: &str = "registry.scheduling-hooks/v1";
const DATA_SCHEMA_BINDING: &str = "registry.scheduling-hook-data/v1";
const IDEMPOTENCY_DOMAIN: &[u8] = b"scheduling-hook-idempotency-v1";
const ENTITY_ID: &str = "appointment";

const MIN_HMAC_SHA256_KEY_BYTES: usize = 32;
const MAX_ATTEMPT_TIMEOUT_MS: u32 = 10_000;
const MAXIMUM_ATTEMPTS: u8 = 20;
const INITIAL_BACKOFF_MS: i64 = 30_000;
const MAXIMUM_BACKOFF_MS: i64 = 3_600_000;
const BACKOFF_MULTIPLIER: i16 = 2;
const MAXIMUM_PAYLOAD_BYTES: usize = 16 * 1024;
const MAXIMUM_REQUEST_BYTES: usize =
    MAX_DESTINATION_TARGET_BYTES + MAX_DESTINATION_REQUEST_HEADER_BYTES + MAXIMUM_PAYLOAD_BYTES;
const MINIMUM_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAXIMUM_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const IDENTITY_LOCK_TIMEOUT_MS: i32 = 5_000;

const RETRY_DELAYS_MS: [i64; 19] = [
    30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000, 3_600_000, 3_600_000, 3_600_000,
    3_600_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000,
    3_600_000,
];

const APPOINTMENT_FIELDS: &[&str] = &[
    "appointmentId",
    "end",
    "offering",
    "policyRevision",
    "revision",
    "start",
    "state",
];
const CANCELLATION_FIELDS: &[&str] = &["appointmentId", "revision", "state"];

const _: () = assert!(MAXIMUM_PAYLOAD_BYTES <= MAX_DESTINATION_REQUEST_BODY_BYTES);

/// Value-free refusal from hook compilation or deployment activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HookActivationError {
    #[error("the Scheduling hook declaration is invalid")]
    InvalidDeclaration,
    #[error("the Scheduling hook contract is unsupported")]
    UnsupportedContract,
    #[error("the Scheduling hook destination inventory is incomplete")]
    DestinationInventoryMismatch,
    #[error("a Scheduling hook destination binding is invalid")]
    InvalidDestination,
    #[error("a Scheduling hook destination widens the fixed delivery budget")]
    DeliveryBudgetWidening,
    #[error("a Scheduling hook signing secret is unavailable or invalid")]
    InvalidSigningMaterial,
    #[error("the Scheduling hook runtime identity is invalid")]
    InvalidIdentity,
}

/// Value-free refusal while capturing a committed appointment event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HookCaptureError {
    #[error("the Scheduling hook capture is invalid")]
    InvalidCapture,
    #[error("the Scheduling hook outbox is unavailable")]
    Unavailable,
}

/// The immutable Scheduling identity a hook worker must observe in every
/// transaction before it reads or changes delivery state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookRuntimeIdentity {
    pub scheduling_id: String,
    pub policy_revision: i64,
    pub policy_digest: String,
}

/// Validated and compiled Scheduling observer declarations.
#[derive(Clone, Debug)]
pub struct CompiledHooks {
    hooks: Vec<CompiledHook>,
    destination_ids: BTreeSet<String>,
    schema_fingerprint: String,
}

#[derive(Clone, Debug)]
struct CompiledHook {
    id: String,
    trigger: String,
    projection: Vec<String>,
    destination_id: String,
    data_schema: String,
}

impl CompiledHooks {
    /// Compile the shared declaration shape into Scheduling's closed observer
    /// contract. Callers may safely compile again at runtime even when the
    /// authored policy was checked earlier; no unchecked declaration reaches
    /// capture.
    pub fn compile(declarations: &[HookDeclaration]) -> Result<Self, HookActivationError> {
        validate_hooks(declarations).map_err(|_| HookActivationError::InvalidDeclaration)?;

        let mut hooks = Vec::with_capacity(declarations.len());
        let mut destination_ids = BTreeSet::new();
        for declaration in declarations {
            if !valid_identifier(&declaration.id)
                || declaration.phase != HookPhase::After
                || declaration.when.is_some()
                || declaration.principal.is_some()
            {
                return Err(HookActivationError::UnsupportedContract);
            }
            let destination_id = match &declaration.handler {
                HookHandlerSource::Url { destination_id }
                    if valid_logical_destination_id(destination_id) =>
                {
                    destination_id.clone()
                }
                _ => return Err(HookActivationError::UnsupportedContract),
            };
            let allowed = projection_fields(&declaration.trigger)
                .ok_or(HookActivationError::UnsupportedContract)?;
            if declaration
                .projection
                .iter()
                .any(|field| !allowed.contains(&field.as_str()))
            {
                return Err(HookActivationError::UnsupportedContract);
            }
            let projection = declaration.projection.iter().cloned().collect::<Vec<_>>();
            let data_schema = data_schema(&declaration.trigger, &projection)?;
            destination_ids.insert(destination_id.clone());
            hooks.push(CompiledHook {
                id: declaration.id.clone(),
                trigger: declaration.trigger.clone(),
                projection,
                destination_id,
                data_schema,
            });
        }

        let fingerprint_value = json!({
            "schemaVersion": COMPILED_HOOK_SCHEMA,
            "hooks": hooks.iter().map(|hook| json!({
                "id": hook.id,
                "trigger": hook.trigger,
                "projection": hook.projection,
                "destinationId": hook.destination_id,
                "dataSchema": hook.data_schema,
            })).collect::<Vec<_>>(),
        });
        let schema_fingerprint = canonical_digest(&fingerprint_value)
            .map_err(|_| HookActivationError::InvalidDeclaration)?;
        Ok(Self {
            hooks,
            destination_ids,
            schema_fingerprint,
        })
    }

    #[must_use]
    pub fn schema_fingerprint(&self) -> &str {
        &self.schema_fingerprint
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}

/// Activated observer hooks and their exact deployment bindings.
#[derive(Clone)]
pub struct ActivatedHooks {
    compiled: Arc<CompiledHooks>,
    destinations: Arc<ActivatedDestinations>,
    identity: HookRuntimeIdentity,
    schema: String,
    delivery_source: String,
    payload_retention: Duration,
}

impl std::fmt::Debug for ActivatedHooks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivatedHooks")
            .field("hook_count", &self.compiled.hooks.len())
            .field("destination_count", &self.destinations.bindings.len())
            .field("schema_fingerprint", &self.compiled.schema_fingerprint)
            .field("identity", &self.identity)
            .field("payload_retention", &self.payload_retention)
            .finish()
    }
}

impl ActivatedHooks {
    /// Compile and activate the supplied destination inventory for one
    /// deployed Scheduling policy. It must cover every current declaration;
    /// additional explicit bindings remain available for retained delivery
    /// rows captured under an earlier policy.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(
        declarations: &[HookDeclaration],
        configured: &BTreeMap<String, HookDestinationConfig>,
        secrets: &SecretResolver,
        identity: HookRuntimeIdentity,
        database_schema: String,
        payload_retention: Duration,
    ) -> Result<Self, HookActivationError> {
        let compiled = Arc::new(CompiledHooks::compile(declarations)?);
        validate_identity(&identity, &database_schema, payload_retention)?;
        let destinations = Arc::new(ActivatedDestinations::activate(
            &compiled.destination_ids,
            configured,
            secrets,
        )?);
        let delivery_source = format!("urn:registrystack:scheduling:{}", identity.scheduling_id);
        Ok(Self {
            compiled,
            destinations,
            identity,
            schema: database_schema,
            delivery_source,
            payload_retention,
        })
    }

    #[must_use]
    pub fn schema_fingerprint(&self) -> &str {
        self.compiled.schema_fingerprint()
    }

    #[must_use]
    pub fn destination_binding_digest(&self) -> &str {
        &self.destinations.binding_digest
    }

    /// Capture one canonical envelope and one platform delivery row for every
    /// declaration matching `trigger`, in declaration order and inside the
    /// caller's appointment transaction.
    pub async fn capture(
        &self,
        transaction: &Transaction<'_>,
        trigger: &str,
        claim: &ClaimRow,
    ) -> Result<usize, HookCaptureError> {
        if projection_fields(trigger).is_none() || claim.revision <= 0 {
            return Err(HookCaptureError::InvalidCapture);
        }
        let matching = self
            .compiled
            .hooks
            .iter()
            .filter(|hook| hook.trigger == trigger)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Ok(0);
        }

        let created_at = transaction
            .query_one(
                "SELECT date_trunc('milliseconds', transaction_timestamp())",
                &[],
            )
            .await
            .map_err(|_| HookCaptureError::Unavailable)?
            .try_get::<_, SystemTime>(0)
            .map_err(|_| HookCaptureError::Unavailable)?;
        let retention_seconds = i64::try_from(self.payload_retention.as_secs())
            .map_err(|_| HookCaptureError::InvalidCapture)?;
        let record_reference = format!("/v1/appointments/{}", claim.claim_id);

        for hook in matching {
            let event_id = Uuid::new_v4();
            let id = event_id.to_string();
            let data = projected_claim(
                claim,
                self.identity.policy_revision,
                &hook.trigger,
                &hook.projection,
            )?;
            let envelope = HookEnvelope {
                id: id.clone(),
                event_type: hook.id.clone(),
                source: self.delivery_source.clone(),
                time: created_at.into(),
                subject: EventSubject {
                    record_reference: record_reference.clone(),
                    record_revision: claim.revision,
                },
                dataschema: hook.data_schema.clone(),
                data,
                causation: Causation::root(&id),
            };
            let payload = envelope
                .to_canonical_bytes(&EnvelopeLimits::tightened_to(MAXIMUM_PAYLOAD_BYTES))
                .map_err(|_| HookCaptureError::InvalidCapture)?;
            self.insert_outbox(
                transaction,
                event_id,
                hook,
                claim.revision,
                &record_reference,
                &payload,
                created_at,
                retention_seconds,
            )
            .await?;
            let destination = self
                .destinations
                .bindings
                .get(&hook.destination_id)
                .ok_or(HookCaptureError::InvalidCapture)?;
            insert_delivery(
                transaction,
                &self.schema,
                event_id,
                DeliveryCapture {
                    compiled_delivery_id: &hook.id,
                    handler_kind: HookHandlerKind::Url,
                    logical_destination_id: Some(&hook.destination_id),
                    destination_binding_digest: &destination.binding_digest,
                    package_revision: &self.identity.policy_digest,
                    schema_fingerprint: &self.compiled.schema_fingerprint,
                    data_schema: &hook.data_schema,
                    classification_ceiling: "restricted",
                    authentication_profile: "hmac_sha256_v1",
                    delivery_mode: "after_commit",
                    attempt_timeout_ms: i64::from(MAX_ATTEMPT_TIMEOUT_MS),
                    initial_backoff_ms: INITIAL_BACKOFF_MS,
                    maximum_backoff_ms: MAXIMUM_BACKOFF_MS,
                    exponential_backoff_multiplier: BACKOFF_MULTIPLIER,
                    maximum_attempts: i16::from(MAXIMUM_ATTEMPTS),
                    retry_delays_ms: &RETRY_DELAYS_MS,
                    maximum_payload_bytes: MAXIMUM_PAYLOAD_BYTES as i64,
                    payload: &payload,
                    deployed_attempt_timeout_ms: i64::from(destination.attempt_timeout_ms),
                    deployed_maximum_attempts: i16::from(destination.maximum_attempts),
                    dead_letter: "required",
                    operator_replay: false,
                },
            )
            .await
            .map_err(|_| HookCaptureError::Unavailable)?;
        }
        Ok(self
            .compiled
            .hooks
            .iter()
            .filter(|hook| hook.trigger == trigger)
            .count())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_outbox(
        &self,
        transaction: &Transaction<'_>,
        event_id: Uuid,
        hook: &CompiledHook,
        revision: i64,
        record_reference: &str,
        payload: &[u8],
        created_at: SystemTime,
        retention_seconds: i64,
    ) -> Result<(), HookCaptureError> {
        let sql = format!(
            "INSERT INTO {}.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, application_reference, package_revision,
                  schema_fingerprint, payload, payload_expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9,
                     $10::timestamptz + $11::bigint * interval '1 second', $10)",
            self.schema
        );
        let changed = transaction
            .execute(
                &sql,
                &[
                    &event_id,
                    &hook.id,
                    &hook.trigger,
                    &ENTITY_ID,
                    &record_reference,
                    &revision,
                    &self.identity.policy_digest,
                    &self.compiled.schema_fingerprint,
                    &payload,
                    &created_at,
                    &retention_seconds,
                ],
            )
            .await
            .map_err(|_| HookCaptureError::Unavailable)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(HookCaptureError::Unavailable)
        }
    }

    /// Bind the generic platform service to Scheduling's database identity,
    /// audit destination, destinations, and fixed wire constants.
    #[must_use]
    pub fn delivery_service(
        &self,
        store: PostgresStore,
        audit: SchedulingAudit,
    ) -> HookDeliveryService {
        let seams = SchedulingDeliverySeams {
            store,
            audit,
            destinations: Arc::clone(&self.destinations),
            identity: self.identity.clone(),
            schema: self.schema.clone(),
        };
        HookDeliveryService {
            inner: DeliveryService::new(
                seams,
                DeliveryConfig {
                    schema: self.schema.clone(),
                    idempotency_domain: IDEMPOTENCY_DOMAIN.to_vec(),
                    delivery_source: self.delivery_source.clone(),
                },
            ),
        }
    }
}

#[derive(Clone)]
struct ActivatedDestinations {
    bindings: BTreeMap<String, Arc<ActivatedDestination>>,
    binding_digest: String,
}

impl ActivatedDestinations {
    fn activate(
        expected: &BTreeSet<String>,
        configured: &BTreeMap<String, HookDestinationConfig>,
        secrets: &SecretResolver,
    ) -> Result<Self, HookActivationError> {
        let configured_ids = configured.keys().cloned().collect::<BTreeSet<_>>();
        if !expected.is_subset(&configured_ids) {
            return Err(HookActivationError::DestinationInventoryMismatch);
        }
        let mut bindings = BTreeMap::new();
        let mut digest_values = Vec::with_capacity(configured.len());
        for (logical_id, config) in configured {
            let destination = ActivatedDestination::activate(logical_id, config, secrets)?;
            digest_values.push(destination.digest_value.clone());
            bindings.insert(logical_id.clone(), Arc::new(destination));
        }
        let binding_digest = canonical_digest(&json!({
            "schemaVersion": DESTINATION_BINDING_SCHEMA,
            "destinations": digest_values,
        }))
        .map_err(|_| HookActivationError::InvalidDestination)?;
        Ok(Self {
            bindings,
            binding_digest,
        })
    }
}

struct ActivatedDestination {
    binding_digest: String,
    digest_value: Value,
    request_target: String,
    policy: Arc<EventDestinationPolicy>,
    request_template: EventDestinationRequestTemplate,
    hmac_sha256_key: ProtectedSecret,
    attempt_timeout_ms: u32,
    maximum_attempts: u8,
}

impl ActivatedDestination {
    fn activate(
        logical_id: &str,
        config: &HookDestinationConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, HookActivationError> {
        if !valid_logical_destination_id(logical_id)
            || !(100..=MAX_ATTEMPT_TIMEOUT_MS).contains(&config.attempt_timeout_milliseconds)
            || !(1..=MAXIMUM_ATTEMPTS).contains(&config.maximum_attempts)
        {
            return Err(HookActivationError::DeliveryBudgetWidening);
        }
        let (origin, request_target, profile) = destination_parts(&config.url)?;
        let policy = EventDestinationPolicy::new(logical_id, &origin, profile, &[])
            .map_err(|_| HookActivationError::InvalidDestination)?;
        let request_template = EventDestinationRequestTemplate::event_delivery(
            &request_target,
            MAXIMUM_PAYLOAD_BYTES,
            MAXIMUM_REQUEST_BYTES,
        )
        .map_err(|_| HookActivationError::InvalidDestination)?;
        let hmac_sha256_key = secrets
            .resolve(&config.hmac_sha256_key_ref)
            .map_err(|_| HookActivationError::InvalidSigningMaterial)?;
        if !(MIN_HMAC_SHA256_KEY_BYTES..=MAX_SECRET_BYTES).contains(&hmac_sha256_key.len()) {
            return Err(HookActivationError::InvalidSigningMaterial);
        }
        let digest_value = json!({
            "logicalId": logical_id,
            "url": config.url,
            "hmacSha256KeyRef": config.hmac_sha256_key_ref,
            "attemptTimeoutMilliseconds": config.attempt_timeout_milliseconds,
            "maximumAttempts": config.maximum_attempts,
        });
        let binding_digest = canonical_digest(&json!({
            "schemaVersion": DESTINATION_BINDING_SCHEMA,
            "destination": digest_value,
        }))
        .map_err(|_| HookActivationError::InvalidDestination)?;
        Ok(Self {
            binding_digest,
            digest_value,
            request_target,
            policy: Arc::new(policy),
            request_template,
            hmac_sha256_key,
            attempt_timeout_ms: config.attempt_timeout_milliseconds,
            maximum_attempts: config.maximum_attempts,
        })
    }
}

impl std::fmt::Debug for ActivatedDestination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivatedDestination")
            .field("binding_digest", &self.binding_digest)
            .field("request_target", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("request_template", &self.request_template)
            .field("hmac_sha256_key", &"[REDACTED]")
            .field("attempt_timeout_ms", &self.attempt_timeout_ms)
            .field("maximum_attempts", &self.maximum_attempts)
            .finish()
    }
}

#[derive(Clone)]
struct DestinationBinding(Arc<ActivatedDestination>);

#[async_trait::async_trait]
impl HookDestination for DestinationBinding {
    fn binding_digest(&self) -> &str {
        &self.0.binding_digest
    }

    fn attempt_timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.0.attempt_timeout_ms))
    }

    fn maximum_attempts(&self) -> u8 {
        self.0.maximum_attempts
    }

    fn sign_delivery(
        &self,
        fields: DeliverySignatureFields<'_>,
    ) -> Result<String, DeliverySignatureRefused> {
        sign_v1(
            self.0.hmac_sha256_key.expose_secret(),
            SignatureFields {
                id: fields.id,
                source: fields.source,
                event_type: fields.event_type,
                time: fields.time,
                data_schema: fields.data_schema,
                generation: fields.generation,
                attempt: fields.attempt,
                delivery_time: fields.delivery_time,
                method: "POST",
                request_target: &self.0.request_target,
                content_type: "application/json",
                idempotency_key: fields.idempotency_key,
                body: fields.body,
            },
        )
        .map_err(|_| DeliverySignatureRefused)
    }

    fn render_delivery(
        &self,
        headers: EventDeliveryHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError> {
        self.0.request_template.render_event(headers, body)
    }

    async fn send_delivery(
        &self,
        request: EventDestinationRequest,
        remaining: Duration,
    ) -> Result<DestinationAnswer, DestinationSendError> {
        let response = self.0.policy.send(request, remaining).await?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Ok(DestinationAnswer::NonSuccess { status });
        }
        match response.read_bounded(MAX_OUTPUT_BYTES).await {
            Ok(body) => Ok(DestinationAnswer::Delivered {
                body: body.to_event_answer(),
            }),
            Err(error) => Ok(DestinationAnswer::AnswerRefused(HandlerRunFailure::new(
                match error {
                    DestinationResponseError::BodyTooLarge
                    | DestinationResponseError::BodyLimitTooHigh => {
                        registry_platform_hooks::ErrorCategory::Resource
                    }
                    DestinationResponseError::DeadlineExceeded => {
                        registry_platform_hooks::ErrorCategory::Deadline
                    }
                    DestinationResponseError::BodyReadFailed => {
                        registry_platform_hooks::ErrorCategory::Unavailable
                    }
                },
            ))),
        }
    }
}

#[derive(Clone)]
struct SchedulingDeliverySeams {
    store: PostgresStore,
    audit: SchedulingAudit,
    destinations: Arc<ActivatedDestinations>,
    identity: HookRuntimeIdentity,
    schema: String,
}

#[async_trait::async_trait]
impl DeliverySeams for SchedulingDeliverySeams {
    type Destination = DestinationBinding;
    type Handler = NoLocalHandler;

    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
        let client = self
            .store
            .hook_delivery_client()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(Box::new(PooledClient(client)))
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError> {
        transaction
            .execute(
                "SELECT set_config('lock_timeout', $1::text, true)",
                &[&format!("{IDENTITY_LOCK_TIMEOUT_MS}ms")],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        let identity_query = format!(
            "SELECT scheduling_id, policy_revision, policy_digest
               FROM {}.scheduling_meta WHERE singleton FOR SHARE",
            self.schema
        );
        let row = transaction
            .query_opt(&identity_query, &[])
            .await
            .map_err(|_| DeliveryError::Unavailable)?
            .ok_or(DeliveryError::Unavailable)?;
        let matches = row.try_get::<_, String>(0).ok().as_deref()
            == Some(self.identity.scheduling_id.as_str())
            && row.try_get::<_, i64>(1).ok() == Some(self.identity.policy_revision)
            && row.try_get::<_, String>(2).ok().as_deref()
                == Some(self.identity.policy_digest.as_str());
        matches.then_some(()).ok_or(DeliveryError::Unavailable)
    }

    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination> {
        self.destinations
            .bindings
            .get(logical_destination_id)
            .cloned()
            .map(DestinationBinding)
    }

    fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
        None
    }

    async fn apply_proposal(
        &self,
        _application: ProposalApplication<'_>,
    ) -> Result<ProposalOutcome, DeliveryError> {
        Ok(ProposalOutcome::Refused {
            code: bounded_proposal_code("scheduling.hook.proposal_unsupported"),
            summary: bounded_proposal_summary(
                "Scheduling appointment observer hooks cannot propose changes",
            ),
        })
    }

    async fn recover_proposal_receipt(
        &self,
        _recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError> {
        Ok(None)
    }

    async fn recover_proposal_receipt_in_transaction(
        &self,
        _transaction: &Transaction<'_>,
        _recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError> {
        Ok(None)
    }

    /// The platform worker records an attempt's start inside the lease
    /// transaction before it commits, so an attempt is on record before its
    /// request can leave the process and a destination that refuses it rolls
    /// the lease back without egress; a lease whose commit then fails is
    /// answered with a worker interruption. A terminal disposition, an
    /// expiry, and a replay's outcome are recorded only after the transition
    /// commits, so no entry names a transition that rolled back.
    ///
    /// An attempt's start and an operator's replay request are `request`
    /// entries; the terminal disposition and the replay's committed or
    /// refused reset are `response` entries. One attempt's entries share a
    /// correlation built from the hook event, the compiled delivery, the
    /// generation, and the attempt.
    async fn record_audit(&self, record: DeliveryAuditRecord<'_>) -> Result<(), DeliveryError> {
        let audit = json!({
            "event": "scheduling.hook-delivery",
            "hookEventId": record.event_id,
            "compiledDeliveryId": record.compiled_delivery_id,
            "policyDigest": record.package_revision,
            "generation": record.generation,
            "attempt": record.attempt,
            "phase": audit_phase(record.phase),
            "outcome": audit_outcome(record.outcome),
            "disposition": audit_disposition(record.disposition),
        });
        let correlation = format!(
            "{}/{}/{}/{}",
            record.event_id, record.compiled_delivery_id, record.generation, record.attempt
        );
        let entry = match (record.phase, record.outcome) {
            (DeliveryAuditPhase::Attempt, _)
            | (DeliveryAuditPhase::Replay, DeliveryAuditOutcome::ReplayRequested) => {
                AuditEntry::request(SCHEDULING_AUDIT_SCHEMA, correlation, audit)
            }
            (DeliveryAuditPhase::Terminal | DeliveryAuditPhase::Replay, _) => {
                AuditEntry::response(SCHEDULING_AUDIT_SCHEMA, correlation, audit)
            }
        };
        self.audit
            .append(entry)
            .await
            .map_err(|_| DeliveryError::Unavailable)
    }

    fn operational_event(&self, event: DeliveryOperationalEvent) {
        match event {
            DeliveryOperationalEvent::IterationFailed => {
                tracing::warn!(event = "scheduling_hook_delivery_iteration_failed");
            }
            DeliveryOperationalEvent::TransitionFailed(code) => {
                tracing::warn!(
                    event = "scheduling_hook_delivery_transition_failed",
                    code = transition_code(code)
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
enum NoLocalHandler {}

#[async_trait::async_trait]
impl HookHandler for NoLocalHandler {
    fn handler_digest(&self) -> &str {
        match *self {}
    }

    fn attempt_timeout(&self) -> Duration {
        match *self {}
    }

    fn maximum_attempts(&self) -> u8 {
        match *self {}
    }

    async fn run(
        &self,
        _envelope: &[u8],
        _remaining: Duration,
    ) -> Result<Vec<u8>, HandlerRunFailure> {
        match *self {}
    }
}

struct PooledClient(deadpool_postgres::Client);

impl Deref for PooledClient {
    type Target = tokio_postgres::Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Scheduling's usable wrapper around the generic delivery service.
#[derive(Clone)]
pub struct HookDeliveryService {
    inner: DeliveryService<SchedulingDeliverySeams>,
}

impl HookDeliveryService {
    pub async fn deliver_once(&self) -> Result<DeliveryOutcome, DeliveryError> {
        self.inner.deliver_once().await
    }

    pub async fn verify_retained_bindings(&self) -> Result<(), DeliveryError> {
        self.inner.verify_retained_bindings().await
    }

    #[must_use]
    pub fn worker(&self) -> HookDeliveryWorker {
        HookDeliveryWorker {
            inner: DeliveryWorker::new(self.inner.clone()),
        }
    }
}

/// Scheduling's post-commit hook delivery loop.
pub struct HookDeliveryWorker {
    inner: DeliveryWorker<SchedulingDeliverySeams>,
}

impl HookDeliveryWorker {
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        self.inner.run(shutdown).await;
    }
}

fn projected_claim(
    claim: &ClaimRow,
    policy_revision: i64,
    trigger: &str,
    projection: &[String],
) -> Result<Value, HookCaptureError> {
    let mut values = Map::new();
    for field in projection {
        let value = match field.as_str() {
            "appointmentId" => json!(claim.claim_id),
            "offering" => json!(claim.offering),
            "start" => json!(claim.displayed_start),
            "end" => json!(claim.displayed_end),
            "revision" => json!(claim.revision),
            // Bind the event to the policy revision that authorized the
            // operation. A cancellation closes a claim minted under an older
            // revision, so the retained claim's creation revision is not the
            // relevant authority here.
            "policyRevision" => json!(policy_revision),
            "state" => match trigger {
                APPOINTMENT_CONFIRMED_TRIGGER | APPOINTMENT_RESCHEDULED_TRIGGER => {
                    json!("confirmed")
                }
                APPOINTMENT_CANCELLED_TRIGGER => json!("cancelled"),
                _ => return Err(HookCaptureError::InvalidCapture),
            },
            // Actor, reason, duplicate keys, and every credential-adjacent
            // caller value are intentionally not representable here.
            _ => return Err(HookCaptureError::InvalidCapture),
        };
        values.insert(field.clone(), value);
    }
    Ok(Value::Object(values))
}

fn projection_fields(trigger: &str) -> Option<&'static [&'static str]> {
    match trigger {
        APPOINTMENT_CONFIRMED_TRIGGER | APPOINTMENT_RESCHEDULED_TRIGGER => Some(APPOINTMENT_FIELDS),
        APPOINTMENT_CANCELLED_TRIGGER => Some(CANCELLATION_FIELDS),
        _ => None,
    }
}

fn data_schema(trigger: &str, projection: &[String]) -> Result<String, HookActivationError> {
    let digest = canonical_digest(&json!({
        "schemaVersion": DATA_SCHEMA_BINDING,
        "trigger": trigger,
        "projection": projection,
    }))
    .map_err(|_| HookActivationError::InvalidDeclaration)?;
    Ok(format!("urn:registrystack:scheduling:hook-data:{digest}"))
}

fn destination_parts(
    configured: &str,
) -> Result<(String, String, DestinationProfile), HookActivationError> {
    let parsed = Url::parse(configured).map_err(|_| HookActivationError::InvalidDestination)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(HookActivationError::InvalidDestination);
    }
    let profile = match parsed.scheme() {
        "https" => DestinationProfile::ProductionHttps,
        "http"
            if matches!(
                parsed.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("[::1]")
            ) =>
        {
            DestinationProfile::LoopbackDevelopmentHttp
        }
        _ => return Err(HookActivationError::InvalidDestination),
    };
    let request_target = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };
    let mut origin = parsed;
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok((origin.to_string(), request_target, profile))
}

fn validate_identity(
    identity: &HookRuntimeIdentity,
    schema: &str,
    payload_retention: Duration,
) -> Result<(), HookActivationError> {
    if !valid_identifier(&identity.scheduling_id)
        || identity.policy_revision <= 0
        || !valid_sha256_digest(&identity.policy_digest)
        || !valid_schema_name(schema)
        || !(MINIMUM_RETENTION..=MAXIMUM_RETENTION).contains(&payload_retention)
        || payload_retention.subsec_nanos() != 0
    {
        return Err(HookActivationError::InvalidIdentity);
    }
    Ok(())
}

fn valid_logical_destination_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_schema_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_digest(value: &Value) -> Result<String, ()> {
    let canonical = canonicalize_json(value).map_err(|_| ())?;
    let digest = Sha256::digest(canonical);
    Ok(format!("sha256:{}", hex(&digest)))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn bounded_proposal_code(value: &'static str) -> BoundedText<MAX_REFUSAL_CODE_BYTES> {
    BoundedText::new(value.to_owned()).expect("static proposal code fits its bound")
}

fn bounded_proposal_summary(value: &'static str) -> BoundedText<MAX_REFUSAL_SUMMARY_BYTES> {
    BoundedText::new(value.to_owned()).expect("static proposal summary fits its bound")
}

fn audit_phase(value: DeliveryAuditPhase) -> &'static str {
    match value {
        DeliveryAuditPhase::Attempt => "attempt",
        DeliveryAuditPhase::Terminal => "terminal",
        DeliveryAuditPhase::Replay => "replay",
    }
}

fn audit_outcome(value: DeliveryAuditOutcome) -> &'static str {
    match value {
        DeliveryAuditOutcome::AttemptStarted => "attempt_started",
        DeliveryAuditOutcome::Delivered => "delivered",
        DeliveryAuditOutcome::HttpNonSuccess => "http_non_success",
        DeliveryAuditOutcome::DestinationTimeout => "destination_timeout",
        DeliveryAuditOutcome::DestinationResolutionRefused => "destination_resolution_refused",
        DeliveryAuditOutcome::DestinationTransportUnavailable => {
            "destination_transport_unavailable"
        }
        DeliveryAuditOutcome::DestinationPolicyRefused => "destination_policy_refused",
        DeliveryAuditOutcome::DestinationBindingRefused => "destination_binding_refused",
        DeliveryAuditOutcome::HandlerBindingRefused => "handler_binding_refused",
        DeliveryAuditOutcome::HandlerDeadline => "handler_deadline",
        DeliveryAuditOutcome::HandlerResource => "handler_resource",
        DeliveryAuditOutcome::HandlerExecution => "handler_execution",
        DeliveryAuditOutcome::HandlerSource => "handler_source",
        DeliveryAuditOutcome::HandlerUnavailable => "handler_unavailable",
        DeliveryAuditOutcome::PayloadRefused => "payload_refused",
        DeliveryAuditOutcome::PayloadExpired => "payload_expired",
        DeliveryAuditOutcome::WorkerInterrupted => "worker_interrupted",
        DeliveryAuditOutcome::ReplayRequested => "replay_requested",
        DeliveryAuditOutcome::ReplayCommitted => "replay_committed",
        DeliveryAuditOutcome::ReplayRefused => "replay_refused",
    }
}

fn audit_disposition(value: DeliveryAuditDisposition) -> &'static str {
    match value {
        DeliveryAuditDisposition::Leased => "leased",
        DeliveryAuditDisposition::Delivered => "delivered",
        DeliveryAuditDisposition::RetryPending => "retry_pending",
        DeliveryAuditDisposition::DeadLettered => "dead_lettered",
        DeliveryAuditDisposition::Expired => "expired",
        DeliveryAuditDisposition::ReplayPending => "replay_pending",
    }
}

fn transition_code(
    value: registry_platform_hooks::delivery::DeliveryTransitionCode,
) -> &'static str {
    use registry_platform_hooks::delivery::DeliveryTransitionCode;
    match value {
        DeliveryTransitionCode::ClaimIdentityRefused => "claim_identity_refused",
        DeliveryTransitionCode::ClaimRecoveryFailed => "claim_recovery_failed",
        DeliveryTransitionCode::ClaimSelectFailed => "claim_select_failed",
        DeliveryTransitionCode::ClaimPolicyRefused => "claim_policy_refused",
        DeliveryTransitionCode::ClaimUpdateFailed => "claim_update_failed",
        DeliveryTransitionCode::ClaimAuditFailed => "claim_audit_failed",
        DeliveryTransitionCode::ClaimCommitFailed => "claim_commit_failed",
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use registry_scheduling_core::LedgerKind;

    use super::*;
    use crate::store::ClaimState;

    #[test]
    fn projections_disclose_only_the_requested_closed_fields() {
        let now = Utc::now();
        let claim = ClaimRow {
            claim_id: Uuid::new_v4(),
            kind: LedgerKind::Booking,
            state: ClaimState::Active,
            offering: "consultation".to_owned(),
            supply_id: "secret-resource".to_owned(),
            channel: Some("secret-channel".to_owned()),
            displayed_start: now,
            displayed_end: now + TimeDelta::minutes(30),
            occupied_start: now - TimeDelta::minutes(5),
            occupied_end: now + TimeDelta::minutes(35),
            units: 1,
            duplicate_key: Some("secret-duplicate-key".to_owned()),
            hold_expires_at: None,
            revision: 4,
            policy_revision: 2,
            actor: "secret-actor".to_owned(),
            reason: Some("secret-reason".to_owned()),
            created_at: now,
            closed_at: None,
        };
        let projection = [
            "appointmentId",
            "offering",
            "start",
            "end",
            "revision",
            "policyRevision",
            "state",
        ]
        .map(str::to_owned);

        let projected = projected_claim(&claim, 9, APPOINTMENT_CONFIRMED_TRIGGER, &projection)
            .expect("the closed projection is valid");

        assert_eq!(projected["policyRevision"], json!(9));
        assert_eq!(projected["state"], json!("confirmed"));
        let serialized = projected.to_string();
        for canary in [
            "secret-resource",
            "secret-channel",
            "secret-duplicate-key",
            "secret-actor",
            "secret-reason",
        ] {
            assert!(!serialized.contains(canary), "projection leaked {canary}");
        }
    }

    #[test]
    fn cancellation_projection_uses_the_public_terminal_state() {
        let now = Utc::now();
        let claim = ClaimRow {
            claim_id: Uuid::new_v4(),
            kind: LedgerKind::Booking,
            state: ClaimState::Cancelled,
            offering: "consultation".to_owned(),
            supply_id: "resource".to_owned(),
            channel: None,
            displayed_start: now,
            displayed_end: now + TimeDelta::minutes(30),
            occupied_start: now,
            occupied_end: now + TimeDelta::minutes(30),
            units: 1,
            duplicate_key: None,
            hold_expires_at: None,
            revision: 5,
            policy_revision: 2,
            actor: "actor".to_owned(),
            reason: Some("private reason".to_owned()),
            created_at: now,
            closed_at: Some(now),
        };
        let projection = ["appointmentId", "revision", "state"].map(str::to_owned);

        let projected = projected_claim(&claim, 9, APPOINTMENT_CANCELLED_TRIGGER, &projection)
            .expect("the cancellation projection is valid");

        assert_eq!(projected["state"], json!("cancelled"));
        assert!(!projected.to_string().contains("private reason"));
    }

    #[test]
    fn destination_parsing_accepts_only_explicit_loopback_http() {
        for url in [
            "http://localhost:8080/hooks",
            "http://127.0.0.1:8080/hooks",
            "http://[::1]:8080/hooks",
            "https://receiver.example/hooks",
        ] {
            destination_parts(url).expect("the reviewed destination is valid");
        }
        assert!(destination_parts("http://receiver.example/hooks").is_err());
        assert!(destination_parts("https://receiver.example/hooks?token=secret").is_err());
    }
}
