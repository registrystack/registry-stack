// SPDX-License-Identifier: Apache-2.0

//! Scheduling's closed after-commit appointment observer runtime.
//!
//! The shared hook crate owns the envelope and delivery state machine. This
//! module owns Scheduling's policy: three appointment lifecycle triggers,
//! caller-selected projections over a closed set of non-attributable claim
//! fields, URL handlers only, exact deployment destination activation, and a
//! worker that can observe an answer but can never apply a proposal.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::SecretResolver;
use registry_platform_hooks::delivery::{
    hook_audit_entry, insert_delivery, url_destination_address, verify_active_package,
    DeliveryAuditRecord, DeliveryCapture, DeliveryConfig, DeliveryConnection, DeliveryError,
    DeliveryOperationalEvent, DeliveryOutcome, DeliverySeams, DeliveryService, DeliveryWorker,
    HookHandlerBinding, NoLocalHandler, PooledConnection, ProposalApplication, ProposalOutcome,
    ProposalReceiptRecovery, SharedUrlDestination, UrlDestination, UrlDestinationError,
    UrlDestinationParts,
};
use registry_platform_hooks::{
    exponential_retry_delays_ms, validate_hooks, BoundedText, Causation, EnvelopeLimits,
    EventSubject, HookCapabilities, HookDeclaration, HookEnvelope, HookHandlerKind,
    HookHandlerSource, HookPhase, MAX_REFUSAL_CODE_BYTES, MAX_REFUSAL_SUMMARY_BYTES,
};
use registry_platform_httputil::destination::{
    EventDestinationPolicy, MAX_DESTINATION_REQUEST_BODY_BYTES,
};
use registry_scheduling_core::{
    valid_identifier, APPOINTMENT_CANCELLED_TRIGGER, APPOINTMENT_CONFIRMED_TRIGGER,
    APPOINTMENT_OBSERVER_FIELDS, APPOINTMENT_RESCHEDULED_TRIGGER, CANCELLATION_OBSERVER_FIELDS,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::{SchedulingAudit, SCHEDULING_AUDIT_SCHEMA};
use crate::config::{
    valid_logical_destination_id, HookDestinationConfig, MAX_HOOK_ATTEMPTS,
    MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use crate::store::{activation_layout, ClaimRow, PostgresStore};

const DESTINATION_BINDING_SCHEMA: &str = "registry.scheduling-hook-destinations/v1";
const COMPILED_HOOK_SCHEMA: &str = "registry.scheduling-hooks/v1";
const DATA_SCHEMA_BINDING: &str = "registry.scheduling-hook-data/v1";
const IDEMPOTENCY_DOMAIN: &[u8] = b"scheduling-hook-idempotency-v1";
const ENTITY_ID: &str = "appointment";
/// The refusal code retained with a delivery whose destination answered with
/// a proposal. Each dotted segment is lowercase kebab-case.
const PROPOSAL_UNSUPPORTED_CODE: &str = "scheduling.hook.proposal-unsupported";

const INITIAL_BACKOFF_MS: u32 = 30_000;
const MAXIMUM_BACKOFF_MS: u32 = 3_600_000;
const BACKOFF_MULTIPLIER: u8 = 2;
const MAXIMUM_PAYLOAD_BYTES: usize = 16 * 1024;
const MINIMUM_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAXIMUM_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const IDENTITY_LOCK_TIMEOUT_MS: u32 = 5_000;

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

/// The Scheduling identity a hook worker serves. `database_id` and
/// `package_digest` are what the activation record must still name in every
/// transaction before the worker reads or changes delivery state; the
/// deployment id and policy shape the events a capture writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookRuntimeIdentity {
    pub database_id: String,
    pub package_digest: String,
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
        HookCapabilities::URL_ONLY
            .check_declarations(declarations)
            .map_err(|_| HookActivationError::UnsupportedContract)?;

        let mut hooks = Vec::with_capacity(declarations.len());
        let mut destination_ids = BTreeSet::new();
        for declaration in declarations {
            if !valid_identifier(&declaration.id) || declaration.phase != HookPhase::After {
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
    retry_delays_ms: Arc<[i64]>,
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
            retry_delays_ms: retry_delays_ms().into(),
        })
    }

    #[must_use]
    pub fn schema_fingerprint(&self) -> &str {
        self.compiled.schema_fingerprint()
    }

    /// Compile `declarations` and resolve every destination they name with
    /// its signing material, as [`Self::activate`] does, without a runtime
    /// identity, and keep nothing. Operator tooling reports with it that a
    /// candidate's hooks cannot run before anything is planned or applied.
    pub fn check_destinations(
        declarations: &[HookDeclaration],
        configured: &BTreeMap<String, HookDestinationConfig>,
        secrets: &SecretResolver,
    ) -> Result<(), HookActivationError> {
        let compiled = CompiledHooks::compile(declarations)?;
        ActivatedDestinations::activate(&compiled.destination_ids, configured, secrets)?;
        Ok(())
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
                    destination_binding_digest: destination.binding_digest(),
                    package_revision: &self.identity.policy_digest,
                    schema_fingerprint: &self.compiled.schema_fingerprint,
                    data_schema: &hook.data_schema,
                    classification_ceiling: "restricted",
                    authentication_profile: "hmac-sha256-v1",
                    delivery_mode: "after-commit",
                    attempt_timeout_ms: i64::from(MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS),
                    initial_backoff_ms: i64::from(INITIAL_BACKOFF_MS),
                    maximum_backoff_ms: i64::from(MAXIMUM_BACKOFF_MS),
                    exponential_backoff_multiplier: i16::from(BACKOFF_MULTIPLIER),
                    maximum_attempts: i16::from(MAX_HOOK_ATTEMPTS),
                    retry_delays_ms: &self.retry_delays_ms,
                    maximum_payload_bytes: MAXIMUM_PAYLOAD_BYTES as i64,
                    payload: &payload,
                    deployed_attempt_timeout_ms: i64::try_from(
                        destination.attempt_timeout().as_millis(),
                    )
                    .map_err(|_| HookCaptureError::InvalidCapture)?,
                    deployed_maximum_attempts: i16::from(destination.maximum_attempts()),
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
    bindings: BTreeMap<String, Arc<UrlDestination>>,
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
            let (destination, digest_value) = activate_destination(logical_id, config, secrets)?;
            digest_values.push(digest_value);
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

/// Activate one configured destination, returning it with the non-secret
/// value its binding digest and the inventory digest cover.
fn activate_destination(
    logical_id: &str,
    config: &HookDestinationConfig,
    secrets: &SecretResolver,
) -> Result<(UrlDestination, Value), HookActivationError> {
    if !valid_logical_destination_id(logical_id) || !config.within_delivery_budget() {
        return Err(HookActivationError::DeliveryBudgetWidening);
    }
    let address = url_destination_address(&config.url)
        .map_err(|_| HookActivationError::InvalidDestination)?;
    let policy = EventDestinationPolicy::new(logical_id, &address.origin, address.profile, &[])
        .map_err(|_| HookActivationError::InvalidDestination)?;
    let hmac_sha256_key = secrets
        .resolve(&config.hmac_sha256_key_ref)
        .map_err(|_| HookActivationError::InvalidSigningMaterial)?;
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
    let destination = UrlDestination::new(UrlDestinationParts {
        binding_digest,
        request_target: address.request_target,
        policy,
        maximum_payload_bytes: MAXIMUM_PAYLOAD_BYTES,
        hmac_sha256_key,
        attempt_timeout: Duration::from_millis(u64::from(config.attempt_timeout_milliseconds)),
        maximum_attempts: config.maximum_attempts,
    })
    .map_err(|error| match error {
        UrlDestinationError::InvalidBinding => HookActivationError::InvalidDestination,
        UrlDestinationError::InvalidSigningMaterial => HookActivationError::InvalidSigningMaterial,
    })?;
    Ok((destination, digest_value))
}

/// The delays between attempts: from 30 seconds, doubling, capped at one
/// hour, one delay between each pair of the attempt ceiling's attempts.
fn retry_delays_ms() -> Vec<i64> {
    exponential_retry_delays_ms(
        INITIAL_BACKOFF_MS,
        MAXIMUM_BACKOFF_MS,
        u32::from(BACKOFF_MULTIPLIER),
        MAX_HOOK_ATTEMPTS,
    )
    .into_iter()
    .map(i64::from)
    .collect()
}

#[derive(Clone)]
struct SchedulingDeliverySeams {
    store: PostgresStore,
    audit: SchedulingAudit,
    destinations: Arc<ActivatedDestinations>,
    identity: HookRuntimeIdentity,
}

#[async_trait::async_trait]
impl DeliverySeams for SchedulingDeliverySeams {
    type Destination = SharedUrlDestination;
    type Handler = NoLocalHandler;

    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
        let client = self
            .store
            .hook_delivery_client()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(PooledConnection::boxed(client))
    }

    /// The activation record must still name the package this worker was
    /// started with, for this database.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError> {
        verify_active_package(
            transaction,
            &activation_layout(),
            &self.identity.database_id,
            &self.identity.package_digest,
            IDENTITY_LOCK_TIMEOUT_MS,
        )
        .await
    }

    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination> {
        self.destinations
            .bindings
            .get(logical_destination_id)
            .cloned()
            .map(SharedUrlDestination)
    }

    fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
        None
    }

    async fn apply_proposal(
        &self,
        _application: ProposalApplication<'_>,
    ) -> Result<ProposalOutcome, DeliveryError> {
        Ok(ProposalOutcome::Refused {
            code: bounded_proposal_code(PROPOSAL_UNSUPPORTED_CODE),
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
        let mut fields = Map::new();
        fields.insert("hookEventId".to_owned(), json!(record.event_id));
        fields.insert(
            "compiledDeliveryId".to_owned(),
            json!(record.compiled_delivery_id),
        );
        fields.insert("policyDigest".to_owned(), json!(record.package_revision));
        let correlation_base = format!(
            "{}/{}/{}/{}",
            record.event_id, record.compiled_delivery_id, record.generation, record.attempt
        );
        let entry = hook_audit_entry(
            SCHEDULING_AUDIT_SCHEMA,
            "scheduling.hook-delivery",
            &correlation_base,
            fields,
            &record,
        )
        .map_err(|_| DeliveryError::Unavailable)?;
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
                    code = code.as_str()
                );
            }
        }
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
        self.inner
            .verify_retained_bindings()
            .await
            .map_err(|_| DeliveryError::Unavailable)
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
        APPOINTMENT_CONFIRMED_TRIGGER | APPOINTMENT_RESCHEDULED_TRIGGER => {
            Some(APPOINTMENT_OBSERVER_FIELDS)
        }
        APPOINTMENT_CANCELLED_TRIGGER => Some(CANCELLATION_OBSERVER_FIELDS),
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

fn validate_identity(
    identity: &HookRuntimeIdentity,
    schema: &str,
    payload_retention: Duration,
) -> Result<(), HookActivationError> {
    if identity.database_id.is_empty()
        || identity.package_digest.is_empty()
        || !valid_identifier(&identity.scheduling_id)
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

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use registry_platform_config::SecretProvider;
    use registry_scheduling_core::LedgerKind;

    use super::*;
    use crate::config::{reads_block, DestinationsConfig, MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS};
    use crate::store::{ClaimOwner, ClaimState};

    /// Lowercase kebab-case, the spelling of every value a machine matches.
    fn is_kebab_case(word: &str) -> bool {
        !word.is_empty()
            && word.split('-').all(|part| {
                !part.is_empty()
                    && part.chars().all(|character| {
                        character.is_ascii_lowercase() || character.is_ascii_digit()
                    })
            })
            && word.starts_with(|character: char| character.is_ascii_lowercase())
    }

    #[test]
    fn the_proposal_refusal_code_is_dotted_kebab_case() {
        assert_eq!(
            PROPOSAL_UNSUPPORTED_CODE,
            "scheduling.hook.proposal-unsupported"
        );
        assert!(PROPOSAL_UNSUPPORTED_CODE.split('.').all(is_kebab_case));
    }

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
            external_references: Vec::new(),
            hold_expires_at: None,
            revision: 4,
            policy_revision: 2,
            actor: "secret-actor".to_owned(),
            reason: Some("secret-reason".to_owned()),
            created_at: now,
            closed_at: None,
            owner: Some(ClaimOwner {
                issuer: "secret-issuer".to_owned(),
                subject: "secret-subject".to_owned(),
            }),
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
            "secret-issuer",
            "secret-subject",
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
            external_references: Vec::new(),
            hold_expires_at: None,
            revision: 5,
            policy_revision: 2,
            actor: "actor".to_owned(),
            reason: Some("private reason".to_owned()),
            created_at: now,
            closed_at: Some(now),
            owner: None,
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
            url_destination_address(url).expect("the reviewed destination is valid");
        }
        assert!(url_destination_address("http://receiver.example/hooks").is_err());
        assert!(url_destination_address("https://receiver.example/hooks?token=secret").is_err());
    }

    /// The derived schedule is the one every retained delivery row records:
    /// from 30 seconds, doubling, capped at one hour, one delay between each
    /// pair of the attempt ceiling's attempts.
    #[test]
    fn the_retry_schedule_doubles_from_thirty_seconds_to_one_hour() {
        let mut expected = vec![
            30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000,
        ];
        expected.resize(usize::from(MAX_HOOK_ATTEMPTS) - 1, 3_600_000);
        assert_eq!(retry_delays_ms(), expected);
    }

    /// Whether the runtime configuration's reader accepts `config` bound to
    /// the hook destination `id`.
    fn configuration_accepts(id: &str, config: &HookDestinationConfig) -> bool {
        reads_block::<DestinationsConfig>(&json!({"hooks": {id: {
            "url": config.url,
            "hmacSha256KeyRef": config.hmac_sha256_key_ref,
            "attemptTimeoutMilliseconds": config.attempt_timeout_milliseconds,
            "maximumAttempts": config.maximum_attempts,
        }}}))
    }

    /// Activation refuses a binding as a budget widening exactly when the
    /// runtime configuration refuses it, at each bound's edge on both sides,
    /// so a bound moved in the configuration moves activation with it.
    #[test]
    fn activation_refuses_exactly_the_bindings_the_configuration_refuses() {
        // No enabled provider resolves the signing key, so a binding inside
        // the budget is refused one step later, for its signing material.
        let secrets = SecretResolver::new([SecretProvider::Environment], "/")
            .expect("the test secret resolver");
        let binding = |timeout: u32, attempts: u8| HookDestinationConfig {
            url: "https://events.example.test/scheduling".to_owned(),
            hmac_sha256_key_ref: "secret:file/hook-key".to_owned(),
            attempt_timeout_milliseconds: timeout,
            maximum_attempts: attempts,
        };
        let id = "appointment-events".to_owned();
        let mut cases = Vec::new();
        for timeout in [
            0,
            MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS - 1,
            MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
            MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
            MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS + 1,
            u32::MAX,
        ] {
            cases.push((id.clone(), binding(timeout, 8)));
        }
        for attempts in [0, 1, MAX_HOOK_ATTEMPTS, MAX_HOOK_ATTEMPTS + 1, u8::MAX] {
            cases.push((id.clone(), binding(5_000, attempts)));
        }
        for id in [
            "a".to_owned(),
            "events_2".to_owned(),
            "a".repeat(64),
            "a".repeat(65),
            String::new(),
            "Events".to_owned(),
            "2events".to_owned(),
            "-events".to_owned(),
            "events.v1".to_owned(),
            "\u{e9}v\u{e9}nements".to_owned(),
        ] {
            cases.push((id, binding(5_000, 8)));
        }
        let mut accepted = 0;
        for (id, config) in cases {
            let configured = configuration_accepts(&id, &config);
            let activated = activate_destination(&id, &config, &secrets).map(drop);
            if configured {
                accepted += 1;
                assert!(
                    matches!(activated, Err(HookActivationError::InvalidSigningMaterial)),
                    "activation refused {id:?} {config:?} for its budget, which the configuration accepts"
                );
            } else {
                assert!(
                    matches!(activated, Err(HookActivationError::DeliveryBudgetWidening)),
                    "activation did not refuse {id:?} {config:?}, which the configuration refuses"
                );
            }
        }
        assert_eq!(
            accepted, 7,
            "every accepted edge reached the signing material"
        );
    }
}
