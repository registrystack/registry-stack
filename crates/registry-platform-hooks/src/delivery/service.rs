// SPDX-License-Identifier: Apache-2.0

//! The at-least-once delivery worker: claim, send, finalize, and the
//! operator status and replay surface.
//!
//! This is the moved delivery core. Claim, lease/CAS, lease reaping, retry
//! scheduling, dead-lettering, payload expiry, and operator replay run in
//! [`registry_platform_dispatch::postgres::Dispatcher`] over the delivery
//! state table, through the hook store in `store.rs`; attempt-budget
//! accounting, idempotency-key construction, and transport-vs-deadline
//! classification keep the behavior they had while the worker lived in the
//! owning product's runtime. Every product-owned input arrives through the
//! seams, and the worker sends the captured envelope bytes unchanged, with the
//! delivery attributes the transport carries beside them.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_dispatch::postgres::{
    DispatchConfig, DispatchOutcome, DispatchTransport, Dispatcher, Fence, JobKey, JobTable,
    LeasedJob, LeasedReadError, SelectSql,
};
use registry_platform_dispatch::{
    idempotency_key, remaining_attempt_budget, DispatchError, FailureCode, SendOutcome, Sent,
};
use registry_platform_httputil::destination::{DestinationSendError, EventDeliveryHeaders};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::time::Instant;
use uuid::Uuid;

use super::seams::{
    DeliveryAuditOutcome, DeliveryError, DeliveryOperationalEvent, DeliverySeams,
    DeliverySignatureFields, DestinationAnswer, HookDestination, HookHandler, HookHandlerBinding,
    ProposalApplication, ProposalOutcome, ProposalReceiptRecovery,
};
use super::store::{
    attempt_timeout_bound, binding_is_activated, HookJob, HookStore, DISPATCH_SQL, ID_COLUMN,
    PART_COLUMN, REPLAYABLE, STATE_TABLE,
};
use crate::delivery_schema;
use crate::envelope::{EnvelopeLimits, HookEnvelope};
use crate::{ErrorCategory, HandlerOutputLimits, HookHandlerKind, HookMessage};

impl From<tokio_postgres::Error> for DeliveryError {
    fn from(_error: tokio_postgres::Error) -> Self {
        Self::Unavailable
    }
}

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The columns one attempt reloads under its live lease: the stored
/// envelope and the delivery row it must agree with.
const MATERIAL_SELECT: SelectSql = SelectSql {
    columns: "outbox.event_type, outbox.payload,
              outbox.package_revision, outbox.schema_fingerprint,
              delivery.destination_binding_digest,
              delivery.logical_destination_id,
              delivery.maximum_payload_bytes,
              delivery.payload_digest,
              delivery.deployed_attempt_timeout_ms,
              delivery.deployed_maximum_attempts,
              delivery.authentication_profile,
              delivery.delivery_mode,
              delivery.dead_letter,
              delivery.data_schema,
              outbox.created_at",
    joins: "JOIN {schema}.registry_webhook_deliveries AS delivery
              ON delivery.event_id = state.event_id
             AND delivery.compiled_delivery_id = state.compiled_delivery_id
            JOIN {schema}.registry_outbox AS outbox
              ON outbox.event_id = delivery.event_id
             AND outbox.package_revision = delivery.package_revision
             AND outbox.schema_fingerprint = delivery.schema_fingerprint",
    predicate: "outbox.payload IS NOT NULL
                AND outbox.payload_expires_at > transaction_timestamp()",
};
pub const MAX_DELIVERY_STATUS_RESULTS: u16 = 100;

/// The product-supplied constants the worker cannot derive.
///
/// The adopting product passes its own values; the values it used before the
/// move keep the bytes on the wire identical.
pub struct DeliveryConfig {
    /// The product schema that holds the delivery tables. The name is
    /// interpolated into SQL, so only a plain lowercase SQL identifier is
    /// accepted.
    pub schema: String,
    /// The product's idempotency-key domain, bound into every delivery
    /// idempotency key. It must stay stable for the life of retained work,
    /// because a changed domain changes every future key.
    pub idempotency_domain: Vec<u8>,
    /// The delivery source identity sent with every delivery (`ce-source`
    /// and the signed source component): the producing product and
    /// deployment identity.
    pub delivery_source: String,
}

/// The delivery worker over one product's seams.
#[derive(Clone)]
pub struct DeliveryService<S: DeliverySeams> {
    dispatcher: Dispatcher<HookStore<S>>,
    schema: String,
    idempotency_domain: Vec<u8>,
    delivery_source: String,
}

impl<S: DeliverySeams> DeliveryService<S> {
    /// Bind the worker to one product's seams and constants.
    ///
    /// # Panics
    ///
    /// Panics when `config.schema` is not a plain lowercase SQL identifier of
    /// at most 63 bytes, because the schema name is interpolated into SQL.
    #[must_use]
    pub fn new(seams: S, config: DeliveryConfig) -> Self {
        let schema = delivery_schema::require_plain_identifier(&config.schema).to_owned();
        let table = JobTable::new(&schema, STATE_TABLE, ID_COLUMN, PART_COLUMN)
            .expect("the delivery state table is a plain identifier in a plain schema");
        let dispatcher = Dispatcher::new(
            HookStore {
                seams,
                schema: schema.clone(),
            },
            DispatchConfig {
                table,
                sql: DISPATCH_SQL,
                attempt_timeout: attempt_timeout_bound(),
                replayable: REPLAYABLE,
            },
        )
        .expect("the hook delivery statements are contained and well formed");
        Self {
            dispatcher,
            schema,
            idempotency_domain: config.idempotency_domain,
            delivery_source: config.delivery_source,
        }
    }

    fn seams(&self) -> &S {
        &self.dispatcher.store().seams
    }

    /// Claim, audit, send, settle, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization. An accepted answer that is a proposal is applied
    /// through the product's apply seam between the answer and
    /// finalization; an uncertain apply leaves the lease for expiry
    /// recovery rather than recording a disposition.
    pub async fn deliver_once(&self) -> Result<DeliveryOutcome, DeliveryError> {
        match self
            .dispatcher
            .dispatch_once(&HookTransport { service: self })
            .await?
        {
            DispatchOutcome::Idle => Ok(DeliveryOutcome::Idle),
            DispatchOutcome::Delivered => Ok(DeliveryOutcome::Delivered),
            DispatchOutcome::RetryScheduled => Ok(DeliveryOutcome::RetryScheduled),
            DispatchOutcome::DeadLettered => Ok(DeliveryOutcome::DeadLettered),
            // Hook policies retry an uncertain attempt and carry no job
            // expiry, so the core never ends a hook attempt in either.
            DispatchOutcome::Unknown | DispatchOutcome::Expired => Err(DeliveryError::Unavailable),
        }
    }

    /// Refuse startup or operator use if retained work cannot use its exact
    /// captured destination under the active deployment bindings.
    pub async fn verify_retained_bindings(&self) -> Result<(), DeliveryError> {
        let mut client = self.seams().connection().await?;
        let transaction = client.transaction().await?;
        self.seams().verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                &self.sql(
                    "SELECT DISTINCT delivery.handler_kind,
                                 delivery.logical_destination_id,
                                 delivery.compiled_delivery_id,
                                 delivery.package_revision,
                                 delivery.destination_binding_digest
                   FROM {schema}.registry_webhook_delivery_state AS state
                   JOIN {schema}.registry_webhook_deliveries AS delivery
                     ON delivery.event_id = state.event_id
                    AND delivery.compiled_delivery_id = state.compiled_delivery_id
                   JOIN {schema}.registry_outbox AS outbox
                     ON outbox.event_id = delivery.event_id
                  WHERE (
                            state.state IN ('pending', 'leased')
                            OR (
                                state.state = 'dead_lettered'
                                AND delivery.operator_replay
                            )
                        )
                    AND outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at > transaction_timestamp()",
                ),
                &[],
            )
            .await?;
        for row in rows {
            let handler_kind = bounded_text(&row, 0, 8)
                .ok()
                .and_then(|kind| HookHandlerKind::from_spelling(&kind));
            let logical_destination_id = row
                .try_get::<_, Option<String>>(1)?
                .filter(|id| id.len() <= 64);
            let compiled_delivery_id = bounded_delivery_id(&row, 2)?;
            let package_revision = bounded_text(&row, 3, 256)?;
            let destination_binding_digest = bounded_text(&row, 4, 71)?;
            // The binding a retained row must still use is the one it was
            // written against: for the `url` kind that is the activated
            // destination, and for a local kind it is the reviewed program
            // the deployed package holds under the same digest.
            let binding_activated = binding_is_activated(
                self.seams(),
                handler_kind,
                logical_destination_id.as_deref(),
                &compiled_delivery_id,
                &package_revision,
                &destination_binding_digest,
            );
            if !binding_activated {
                return Err(DeliveryError::Unavailable);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Return bounded, value-free pending and terminal operator metadata.
    pub async fn list(&self, limit: u16) -> Result<Vec<DeliveryStatus>, DeliveryError> {
        if limit == 0 || limit > MAX_DELIVERY_STATUS_RESULTS {
            return Err(DeliveryError::Unavailable);
        }
        let mut client = self.seams().connection().await?;
        let transaction = client.transaction().await?;
        self.seams().verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                &self.sql(
                    "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.state, state.attempt,
                        outbox.payload IS NOT NULL
                            AND outbox.payload_expires_at > transaction_timestamp(),
                        outbox.payload_expires_at
                   FROM {schema}.registry_webhook_delivery_state AS state
                   JOIN {schema}.registry_outbox AS outbox
                     ON outbox.event_id = state.event_id
                  WHERE state.state IN ('pending', 'dead_lettered', 'expired')
                  ORDER BY state.updated_at DESC, state.event_id,
                           state.compiled_delivery_id
                  LIMIT $1",
                ),
                &[&i64::from(limit)],
            )
            .await?;
        let mut statuses = Vec::with_capacity(rows.len());
        for row in rows {
            let event_id = row.try_get::<_, Uuid>(0)?;
            let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
            let generation = row.try_get::<_, i64>(2)?;
            let stored_state = bounded_text(&row, 3, 32)?;
            let attempt = row.try_get::<_, i16>(4)?;
            let payload_available = row.try_get::<_, bool>(5)?;
            let payload_expires_at = row.try_get::<_, SystemTime>(6)?;
            let state = delivery_status_kind(&stored_state, payload_available)?;
            statuses.push(DeliveryStatus {
                event_id,
                compiled_delivery_id,
                generation,
                state,
                attempt,
                payload_available,
                payload_expires_at: OffsetDateTime::from(payload_expires_at)
                    .format(&Rfc3339)
                    .map_err(|_| DeliveryError::Unavailable)?,
            });
        }
        transaction.commit().await?;
        Ok(statuses)
    }

    /// Reset one terminal delivery for an explicitly permitted operator replay
    /// and return the committed replacement generation.
    ///
    /// Every absent, stale, forbidden, or nonterminal target returns the same
    /// value-free refusal.
    pub async fn replay(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, DeliveryError> {
        if compiled_delivery_id.is_empty()
            || compiled_delivery_id.len() > 256
            || expected_generation <= 0
        {
            return Err(DeliveryError::Unavailable);
        }
        // The binding a replay re-opens must still be the one the row was
        // written against; the hook store refuses the target otherwise.
        let key =
            JobKey::new(event_id, compiled_delivery_id).map_err(|_| DeliveryError::Unavailable)?;
        Ok(self.dispatcher.replay(&key, expected_generation).await?)
    }

    async fn reload_and_send(&self, claim: &DeliveryClaim) -> Result<AttemptResult, DeliveryError> {
        let material = match self.reload_material(claim).await {
            Ok(material) => material,
            Err(MaterialLoadError::Unavailable) => return Err(DeliveryError::Unavailable),
            Err(MaterialLoadError::PayloadRefused) => {
                return Ok(DeliveryAuditOutcome::PayloadRefused.into())
            }
            Err(MaterialLoadError::BindingRefused) => {
                return Ok(material_binding_refusal(claim.handler_kind).into())
            }
        };
        if claim.handler_kind.is_local() {
            return self.run_local_handler(claim, material).await;
        }
        let Some(destination_id) = material.logical_destination_id.as_deref() else {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        };
        let Some(destination) = self.seams().destination(destination_id) else {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        };
        let deployed_timeout_ms = i64::try_from(destination.attempt_timeout().as_millis())
            .map_err(|_| DeliveryError::Unavailable)?;
        if destination.binding_digest() != material.destination_binding_digest
            || deployed_timeout_ms != material.deployed_attempt_timeout_ms
            || i16::from(destination.maximum_attempts()) != material.deployed_maximum_attempts
        {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        }
        let delivery_time = OffsetDateTime::from(claim.attempt_started_at)
            .format(&Rfc3339)
            .map_err(|_| DeliveryError::Unavailable)?;
        let event_time = OffsetDateTime::from(material.event_time)
            .format(&Rfc3339)
            .map_err(|_| DeliveryError::Unavailable)?;
        let event_id = claim.event_id.to_string();
        let source = &self.delivery_source;
        let generation = claim.generation.to_string();
        let attempt = claim.attempt.to_string();
        let idempotency_key = delivery_idempotency_key(
            &self.idempotency_domain,
            claim.event_id,
            &claim.compiled_delivery_id,
            claim.generation,
            &material.payload_digest,
            &material.destination_binding_digest,
        );
        let signature = destination.sign_delivery(DeliverySignatureFields {
            id: &event_id,
            source,
            event_type: &material.event_type,
            time: &event_time,
            data_schema: &material.data_schema,
            generation: &generation,
            attempt: &attempt,
            delivery_time: &delivery_time,
            idempotency_key: &idempotency_key,
            body: &material.body,
        });
        let Ok(signature) = signature else {
            return Ok(DeliveryAuditOutcome::DestinationPolicyRefused.into());
        };
        // The envelope bytes outlive the request: a proposal answer hands
        // them to the product's apply seam after the send returns.
        let envelope = material.body.clone();
        let request = match destination.render_delivery(
            EventDeliveryHeaders {
                id: event_id.as_bytes(),
                source: source.as_bytes(),
                event_type: material.event_type.as_bytes(),
                time: event_time.as_bytes(),
                dataschema: material.data_schema.as_bytes(),
                generation: generation.as_bytes(),
                attempt: attempt.as_bytes(),
                delivery_time: delivery_time.as_bytes(),
                idempotency_key: idempotency_key.as_bytes(),
                signature: signature.as_bytes(),
            },
            material.body,
        ) {
            Ok(request) => request,
            Err(_) => return Ok(DeliveryAuditOutcome::DestinationPolicyRefused.into()),
        };
        let attempt_timeout = Duration::from_millis(
            u64::try_from(material.deployed_attempt_timeout_ms)
                .map_err(|_| DeliveryError::Unavailable)?,
        );
        let Some(remaining) =
            remaining_attempt_budget(attempt_timeout, claim.attempt_started_at, SystemTime::now())
        else {
            return Ok(DeliveryAuditOutcome::DestinationTimeout.into());
        };
        if remaining.is_zero() {
            return Ok(DeliveryAuditOutcome::DestinationTimeout.into());
        }
        let monotonic_deadline = Instant::now() + remaining;
        match destination.send_delivery(request, remaining).await {
            // The destination answered: its bounded body is the handler
            // message, read under the same ceiling and the same canonical
            // rule a local answer is read under. A proposal in that message
            // is applied through the product's seam before finalize.
            Ok(DestinationAnswer::Delivered { body }) => {
                let result = accepted_answer_result(&body);
                self.settle_answer(claim, &envelope, result).await
            }
            Ok(DestinationAnswer::NonSuccess { .. }) => {
                Ok(DeliveryAuditOutcome::HttpNonSuccess.into())
            }
            Ok(DestinationAnswer::AnswerRefused(failure)) => {
                Ok(DeliveryAuditOutcome::handler_failure(failure.category).into())
            }
            Err(error) => Ok(classify_send_error(
                error,
                monotonic_deadline.saturating_duration_since(Instant::now())
                    <= Duration::from_millis(1),
            )
            .into()),
        }
    }

    /// Run one local-kind attempt: resolve the product's handler for the
    /// binding the row recorded, run it over the stored envelope bytes with
    /// the remaining attempt budget, and read its answer.
    ///
    /// A local row is signed by nothing and sent nowhere: the engine holds
    /// the reviewed program, so there is no destination to resolve, no
    /// signature to compute, and no request to render. The binding check is
    /// the same one the `url` path makes, against the handler the product
    /// resolved rather than the destination it activated.
    async fn run_local_handler(
        &self,
        claim: &DeliveryClaim,
        material: DeliveryMaterial,
    ) -> Result<AttemptResult, DeliveryError> {
        let Some(handler) = self.seams().handler(HookHandlerBinding {
            kind: claim.handler_kind,
            compiled_delivery_id: &claim.compiled_delivery_id,
            package_revision: &claim.package_revision,
            handler_digest: &material.destination_binding_digest,
        }) else {
            return Ok(DeliveryAuditOutcome::HandlerBindingRefused.into());
        };
        let deployed_timeout_ms = i64::try_from(handler.attempt_timeout().as_millis())
            .map_err(|_| DeliveryError::Unavailable)?;
        if handler.handler_digest() != material.destination_binding_digest
            || deployed_timeout_ms != material.deployed_attempt_timeout_ms
            || i16::from(handler.maximum_attempts()) != material.deployed_maximum_attempts
        {
            return Ok(DeliveryAuditOutcome::HandlerBindingRefused.into());
        }
        let attempt_timeout = Duration::from_millis(
            u64::try_from(material.deployed_attempt_timeout_ms)
                .map_err(|_| DeliveryError::Unavailable)?,
        );
        let Some(remaining) =
            remaining_attempt_budget(attempt_timeout, claim.attempt_started_at, SystemTime::now())
        else {
            return Ok(DeliveryAuditOutcome::handler_failure(ErrorCategory::Deadline).into());
        };
        if remaining.is_zero() {
            return Ok(DeliveryAuditOutcome::handler_failure(ErrorCategory::Deadline).into());
        }
        match handler.run(&material.body, remaining).await {
            Ok(answer) => {
                let result = accepted_answer_result(&answer);
                self.settle_answer(claim, &material.body, result).await
            }
            Err(failure) => Ok(DeliveryAuditOutcome::handler_failure(failure.category).into()),
        }
    }

    /// Hand an accepted proposal to the product's apply seam.
    ///
    /// The settle step runs after the answer is accepted and before the
    /// finalize transaction, so the disposition the row records is the one
    /// the apply produced and the two can never disagree. An answer that is
    /// not a proposal never reaches the seam. An uncertain apply (`Err`)
    /// propagates: the row keeps its lease and expiry recovery retries, and
    /// the retry relies on the seam's idempotent application identity so the
    /// same answer applies once.
    async fn settle_answer(
        &self,
        claim: &DeliveryClaim,
        envelope: &[u8],
        mut result: AttemptResult,
    ) -> Result<AttemptResult, DeliveryError> {
        let Some(answer) = result.answer.as_ref() else {
            return Ok(result);
        };
        if !matches!(answer.message, HookMessage::Proposal { .. }) {
            result.proposal = self
                .seams()
                .recover_proposal_receipt(ProposalReceiptRecovery {
                    event_id: claim.event_id,
                    compiled_delivery_id: &claim.compiled_delivery_id,
                })
                .await?;
            return Ok(result);
        }
        let outcome = self
            .seams()
            .apply_proposal(ProposalApplication {
                event_id: claim.event_id,
                compiled_delivery_id: &claim.compiled_delivery_id,
                generation: claim.generation,
                attempt: claim.attempt,
                lease_token: claim.lease_token,
                package_revision: &claim.package_revision,
                envelope,
                answer: &answer.bytes,
                answer_digest: &answer.digest,
            })
            .await?;
        result.proposal = Some(outcome);
        Ok(result)
    }

    async fn reload_material(
        &self,
        claim: &DeliveryClaim,
    ) -> Result<DeliveryMaterial, MaterialLoadError> {
        let fence = Fence {
            id: claim.event_id,
            part: &claim.compiled_delivery_id,
            generation: claim.generation,
            attempt: claim.attempt,
            lease_token: claim.lease_token,
        };
        let (material, binding) = self
            .dispatcher
            .read_leased(fence, &MATERIAL_SELECT, decode_material)
            .await
            .map_err(|error| match error {
                LeasedReadError::Unavailable => MaterialLoadError::Unavailable,
                LeasedReadError::Refused(refusal) => refusal,
            })?;
        // A row carries a destination when, and only when, it binds the
        // `url` kind: a local kind runs the engine's own reviewed program
        // and has nowhere to send.
        if material.logical_destination_id.is_some() != (claim.handler_kind == HookHandlerKind::Url)
        {
            return Err(MaterialLoadError::BindingRefused);
        }
        if binding.outbox_package_revision != claim.package_revision
            || binding.outbox_schema_fingerprint.is_empty()
            || binding.authentication_profile != "hmac_sha256_v1"
            || binding.delivery_mode != "after_commit"
            || binding.dead_letter != "required"
            || !(100..=10_000).contains(&material.deployed_attempt_timeout_ms)
            || !(1..=20).contains(&material.deployed_maximum_attempts)
        {
            return Err(MaterialLoadError::BindingRefused);
        }
        accept_stored_envelope(
            &material.body,
            &StoredEnvelope {
                event_id: claim.event_id,
                event_type: &material.event_type,
                source: &self.delivery_source,
                data_schema: &material.data_schema,
                event_time: material.event_time,
                maximum_payload_bytes: binding.maximum_payload_bytes,
                payload_digest: &material.payload_digest,
            },
        )?;
        Ok(material)
    }

    /// Render one SQL template with this deployment's schema name. The
    /// schema was validated as a plain identifier at construction, so the
    /// interpolation is safe.
    fn sql(&self, template: &str) -> String {
        delivery_schema::render(&self.schema, template)
    }
}

/// The post-commit delivery loop: claim, send, finalize, until shutdown.
pub struct DeliveryWorker<S: DeliverySeams> {
    service: DeliveryService<S>,
}

impl<S: DeliverySeams> DeliveryWorker<S> {
    #[must_use]
    pub fn new(service: DeliveryService<S>) -> Self {
        Self { service }
    }

    /// Run until the shutdown watch closes or carries `true`.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let service = self.service;
        loop {
            if *shutdown.borrow() {
                return;
            }
            if service.deliver_once().await.is_err() {
                service
                    .seams()
                    .operational_event(DeliveryOperationalEvent::IterationFailed);
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(WORKER_POLL_INTERVAL) => {}
            }
        }
    }
}

/// One claimed delivery, frozen between the lease commit and finalization.
struct DeliveryClaim {
    event_id: Uuid,
    compiled_delivery_id: String,
    generation: i64,
    attempt: i16,
    attempt_started_at: SystemTime,
    lease_token: Uuid,
    deployed_maximum_attempts: i16,
    package_revision: String,
    handler_kind: HookHandlerKind,
}

struct DeliveryMaterial {
    event_type: String,
    body: Vec<u8>,
    payload_digest: Vec<u8>,
    destination_binding_digest: String,
    logical_destination_id: Option<String>,
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    data_schema: String,
    event_time: SystemTime,
}

/// The reloaded columns the material is checked against before it is
/// accepted.
struct MaterialBinding {
    outbox_package_revision: String,
    outbox_schema_fingerprint: String,
    maximum_payload_bytes: i64,
    authentication_profile: String,
    delivery_mode: String,
    dead_letter: String,
}

enum MaterialLoadError {
    Unavailable,
    BindingRefused,
    PayloadRefused,
}

/// Decode the [`MATERIAL_SELECT`] columns from index `first`.
fn decode_material(
    row: &tokio_postgres::Row,
    first: usize,
) -> Result<(DeliveryMaterial, MaterialBinding), MaterialLoadError> {
    let column = |offset: usize| first + offset;
    let event_type =
        bounded_text(row, column(0), 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let body = row
        .try_get::<_, Option<Vec<u8>>>(column(1))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let body = body.ok_or(MaterialLoadError::PayloadRefused)?;
    let outbox_package_revision =
        bounded_text(row, column(2), 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let outbox_schema_fingerprint =
        bounded_text(row, column(3), 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let destination_binding_digest =
        bounded_text(row, column(4), 71).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let logical_destination_id = row
        .try_get::<_, Option<String>>(column(5))
        .map_err(|_| MaterialLoadError::PayloadRefused)?
        .map(|id| {
            (id.len() <= 64)
                .then_some(id)
                .ok_or(MaterialLoadError::PayloadRefused)
        })
        .transpose()?;
    let maximum_payload_bytes = row
        .try_get::<_, i64>(column(6))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let payload_digest = row
        .try_get::<_, Vec<u8>>(column(7))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let deployed_attempt_timeout_ms = row
        .try_get::<_, i64>(column(8))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let deployed_maximum_attempts = row
        .try_get::<_, i16>(column(9))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let authentication_profile =
        bounded_text(row, column(10), 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let delivery_mode =
        bounded_text(row, column(11), 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let dead_letter =
        bounded_text(row, column(12), 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let data_schema =
        bounded_text(row, column(13), 2_048).map_err(|_| MaterialLoadError::PayloadRefused)?;
    let event_time = row
        .try_get::<_, SystemTime>(column(14))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    Ok((
        DeliveryMaterial {
            event_type,
            body,
            payload_digest,
            destination_binding_digest,
            logical_destination_id,
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            data_schema,
            event_time,
        },
        MaterialBinding {
            outbox_package_revision,
            outbox_schema_fingerprint,
            maximum_payload_bytes,
            authentication_profile,
            delivery_mode,
            dead_letter,
        },
    ))
}

/// One hook attempt as the dispatch core's send: reload the material under
/// the lease, send or run it, settle any proposal, and classify the result.
///
/// Hook delivery retries every failure until its attempts are spent. The
/// only failure that stops early is a dead-lettered proposal, which a retry
/// cannot apply.
struct HookTransport<'a, S: DeliverySeams> {
    service: &'a DeliveryService<S>,
}

#[async_trait]
impl<S: DeliverySeams> DispatchTransport for HookTransport<'_, S> {
    type Job = HookJob;
    type Detail = AttemptResult;

    async fn send(&self, job: &LeasedJob<HookJob>) -> Result<Sent<AttemptResult>, DispatchError> {
        let claim = DeliveryClaim {
            event_id: job.key.id(),
            compiled_delivery_id: job.key.part().to_owned(),
            generation: job.generation,
            attempt: job.attempt,
            attempt_started_at: job.attempt_started_at,
            lease_token: job.lease_token,
            deployed_maximum_attempts: job.policy.maximum_attempts,
            package_revision: job.job.package_revision.clone(),
            handler_kind: job.job.handler_kind,
        };
        let mut result = self.service.reload_and_send(&claim).await?;
        // A proposal may have committed before an earlier worker lost its
        // lease or failed to finalize. If every later attempt fails before
        // accepting an answer, recover that receipt before the last attempt
        // becomes an all-null dead letter. Nonterminal failures keep the
        // ordinary retry path and avoid an extra database lookup.
        if result.proposal.is_none()
            && result.answer.is_none()
            && claim.attempt >= claim.deployed_maximum_attempts
        {
            result.proposal = self
                .service
                .seams()
                .recover_proposal_receipt(ProposalReceiptRecovery {
                    event_id: claim.event_id,
                    compiled_delivery_id: &claim.compiled_delivery_id,
                })
                .await?;
        }
        let outcome = if matches!(result.proposal, Some(ProposalOutcome::DeadLettered { .. })) {
            // A dead-lettered proposal is deterministic: retrying the
            // delivery cannot apply it, so the row is terminal now regardless
            // of the attempts it has left.
            SendOutcome::Permanent {
                code: FailureCode::new("proposal_dead_lettered")
                    .map_err(|_| DispatchError::Unavailable)?,
            }
        } else if result.outcome == DeliveryAuditOutcome::Delivered {
            SendOutcome::Accepted {
                receiver_reference: None,
            }
        } else {
            SendOutcome::Transient { retry_after: None }
        };
        Ok(Sent {
            outcome,
            detail: result,
        })
    }
}

/// What one attempt produced: its audited outcome, the accepted message to
/// record with it when the handler answered, and, when that message carried
/// a proposal, what became of it.
pub(super) struct AttemptResult {
    pub(super) outcome: DeliveryAuditOutcome,
    pub(super) answer: Option<AcceptedAnswer>,
    /// The settled outcome of the proposal the answer carried, set once the
    /// product's apply seam has answered. Always `None` for an answer that
    /// proposed nothing.
    pub(super) proposal: Option<ProposalOutcome>,
}

impl From<DeliveryAuditOutcome> for AttemptResult {
    fn from(outcome: DeliveryAuditOutcome) -> Self {
        Self {
            outcome,
            answer: None,
            proposal: None,
        }
    }
}

/// One accepted handler message and the digest of exactly the bytes
/// recorded for it.
#[derive(Debug)]
pub(super) struct AcceptedAnswer {
    message: HookMessage,
    bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
}

/// The refusal recorded when the delivery row and its binding disagree,
/// named for the kind the row binds.
const fn material_binding_refusal(kind: HookHandlerKind) -> DeliveryAuditOutcome {
    if kind.is_local() {
        DeliveryAuditOutcome::HandlerBindingRefused
    } else {
        DeliveryAuditOutcome::DestinationBindingRefused
    }
}

/// Read one handler answer and turn it into the attempt result it implies.
///
/// An accepted answer is a delivered attempt carrying the message; a refused
/// one is the failure category the taxonomy assigns it, and nothing is
/// recorded.
fn accepted_answer_result(body: &[u8]) -> AttemptResult {
    match accept_handler_answer(body) {
        Ok(answer) => AttemptResult {
            outcome: DeliveryAuditOutcome::Delivered,
            answer: Some(answer),
            proposal: None,
        },
        Err(category) => DeliveryAuditOutcome::handler_failure(category).into(),
    }
}

/// Accept one handler answer: bound it, read it, and digest exactly the
/// bytes that will be recorded.
///
/// Both kinds answer the same way. An empty answer is the `none` answer: a
/// handler that observes and proposes nothing need not write a body, and the
/// record still carries the message it means. Anything else is read as the
/// handler message under the library ceiling, so an answer over the ceiling
/// is a resource failure and a malformed or non-canonical answer is a source
/// failure, exactly as the taxonomy states.
///
/// The recorded bytes are the message's own canonical encoding rather than
/// the bytes as they arrived, so the digest covers what the state holds and
/// the two can never disagree. Reading requires the arriving bytes to equal
/// their canonicalization, so for a non-empty answer the two are the same
/// bytes.
fn accept_handler_answer(body: &[u8]) -> Result<AcceptedAnswer, ErrorCategory> {
    let limits = HandlerOutputLimits::default();
    let message = if body.is_empty() {
        HookMessage::Nothing
    } else {
        HookMessage::from_canonical_json(body, &limits).map_err(|error| error.category())?
    };
    let bytes = message
        .to_canonical_json(&limits)
        .map_err(|error| error.category())?;
    let digest = Sha256::digest(&bytes).into();
    Ok(AcceptedAnswer {
        message,
        bytes,
        digest,
    })
}

/// The proposal bookkeeping values one terminal UPDATE writes: the
/// disposition the answer's proposal earned, the revision an applied
/// proposal produced, or the bounded reason a proposal was refused or
/// dead-lettered.
///
/// A delivered row always states one of `none`, `applied`, or `refused`. A
/// row the proposal path dead-letters states `dead_lettered` with its
/// reason. A row that dead-letters without accepting an answer keeps the
/// all-null legacy shape: it never had a proposal to settle.
pub(super) fn proposal_columns<'a>(
    state: &str,
    proposal: Option<&'a ProposalOutcome>,
) -> Result<ProposalColumns<'a>, DeliveryError> {
    match (state, proposal) {
        ("delivered", None) => Ok(ProposalColumns {
            disposition: Some("none"),
            resulting_revision: None,
            code: None,
            summary: None,
        }),
        ("delivered", Some(ProposalOutcome::Applied { resulting_revision })) => {
            Ok(ProposalColumns {
                disposition: Some("applied"),
                resulting_revision: Some(*resulting_revision),
                code: None,
                summary: None,
            })
        }
        ("delivered", Some(ProposalOutcome::Refused { code, summary })) => Ok(ProposalColumns {
            disposition: Some("refused"),
            resulting_revision: None,
            code: Some(code.as_str()),
            summary: Some(summary.as_str()),
        }),
        ("dead_lettered", Some(ProposalOutcome::DeadLettered { code, summary })) => {
            Ok(ProposalColumns {
                disposition: Some("dead_lettered"),
                resulting_revision: None,
                code: Some(code.as_str()),
                summary: Some(summary.as_str()),
            })
        }
        ("dead_lettered", None) => Ok(ProposalColumns {
            disposition: None,
            resulting_revision: None,
            code: None,
            summary: None,
        }),
        // A settled outcome the finalize routing never pairs with this
        // state: an applied or refused proposal delivers, a dead-lettered
        // one never does.
        _ => Err(DeliveryError::Unavailable),
    }
}

/// The proposal columns one terminal UPDATE writes, borrowed from the
/// settled outcome they record.
pub(super) struct ProposalColumns<'a> {
    pub(super) disposition: Option<&'a str>,
    pub(super) resulting_revision: Option<i64>,
    pub(super) code: Option<&'a str>,
    pub(super) summary: Option<&'a str>,
}

/// What the delivery row and the worker's own configuration say the stored
/// envelope must be.
struct StoredEnvelope<'a> {
    event_id: Uuid,
    event_type: &'a str,
    source: &'a str,
    data_schema: &'a str,
    event_time: SystemTime,
    maximum_payload_bytes: i64,
    payload_digest: &'a [u8],
}

/// Accept the stored envelope bytes the worker is about to deliver unchanged.
///
/// The stored bytes are the delivery body, so the worker re-reads them as an
/// envelope and refuses a row whose headers could disagree with the body it is
/// about to sign. The per-delivery bound measures those same bytes, so an
/// envelope over the bound is refused here rather than sent.
fn accept_stored_envelope(
    body: &[u8],
    expected: &StoredEnvelope<'_>,
) -> Result<(), MaterialLoadError> {
    let maximum = usize::try_from(expected.maximum_payload_bytes)
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let envelope = HookEnvelope::from_canonical_bytes(body, &EnvelopeLimits::tightened_to(maximum))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    if expected.payload_digest.len() != 32
        || expected.payload_digest != Sha256::digest(body).as_slice()
    {
        return Err(MaterialLoadError::PayloadRefused);
    }
    if envelope.id != expected.event_id.to_string()
        || envelope.event_type != expected.event_type
        || envelope.source != expected.source
        || envelope.dataschema != expected.data_schema
        || envelope.time != OffsetDateTime::from(expected.event_time)
    {
        return Err(MaterialLoadError::PayloadRefused);
    }
    Ok(())
}

/// The work result of one delivery iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Idle,
    Delivered,
    RetryScheduled,
    DeadLettered,
}

/// Bounded, value-free operator delivery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatusKind {
    Pending,
    DeadLettered,
    Expired,
}

/// One operator status result: pending and terminal delivery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    pub event_id: Uuid,
    pub compiled_delivery_id: String,
    pub generation: i64,
    pub state: DeliveryStatusKind,
    pub attempt: i16,
    pub payload_available: bool,
    pub payload_expires_at: String,
}

/// The stored delivery state and payload availability, mapped onto the
/// operator's status kind. A pending row whose payload has expired reports
/// `Expired`, exactly as a stored `expired` row does.
fn delivery_status_kind(
    stored_state: &str,
    payload_available: bool,
) -> Result<DeliveryStatusKind, DeliveryError> {
    match stored_state {
        "pending" if payload_available => Ok(DeliveryStatusKind::Pending),
        "pending" | "expired" => Ok(DeliveryStatusKind::Expired),
        "dead_lettered" => Ok(DeliveryStatusKind::DeadLettered),
        _ => Err(DeliveryError::Unavailable),
    }
}

fn classify_send_error(
    error: DestinationSendError,
    deadline_reached: bool,
) -> DeliveryAuditOutcome {
    match error {
        DestinationSendError::DeadlineExceeded
        | DestinationSendError::DeadlineExceededAfterConnect => {
            DeliveryAuditOutcome::DestinationTimeout
        }
        DestinationSendError::ResolutionFailed
        | DestinationSendError::TooManyResolverAnswers
        | DestinationSendError::NoResolverAnswers
        | DestinationSendError::ResolverPortMismatch
        | DestinationSendError::ResolverAddressFamilyMismatch
        | DestinationSendError::LiteralOriginMismatch
        | DestinationSendError::CloudMetadataDenied
        | DestinationSendError::AlwaysDeniedAddress
        | DestinationSendError::PrivateAddressNotAllowed
        | DestinationSendError::NonGlobalAddressDenied
        | DestinationSendError::DevelopmentAddressDenied => {
            DeliveryAuditOutcome::DestinationResolutionRefused
        }
        DestinationSendError::ResolutionCapacityUnavailable
        | DestinationSendError::TlsMaterialUnavailable
        | DestinationSendError::ClientBuildFailed
        | DestinationSendError::TooManyResponseHeaders
        | DestinationSendError::ResponseHeaderBytesExceeded => {
            DeliveryAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::TransportFailed
        | DestinationSendError::TransportFailedAfterConnect
            if deadline_reached =>
        {
            DeliveryAuditOutcome::DestinationTimeout
        }
        DestinationSendError::TransportFailed
        | DestinationSendError::TransportFailedAfterConnect => {
            DeliveryAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::InvalidRemainingTimeout
        | DestinationSendError::InvalidFrozenPolicy
        | DestinationSendError::InvalidFrozenRequest => {
            DeliveryAuditOutcome::DestinationPolicyRefused
        }
    }
}

fn bounded_delivery_id(row: &tokio_postgres::Row, index: usize) -> Result<String, DeliveryError> {
    bounded_text(row, index, 256)
}

pub(super) fn bounded_text(
    row: &tokio_postgres::Row,
    index: usize,
    maximum: usize,
) -> Result<String, DeliveryError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| DeliveryError::Unavailable)?;
    if value.is_empty() || value.len() > maximum {
        return Err(DeliveryError::Unavailable);
    }
    Ok(value)
}

pub(super) fn validate_captured_policy(
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    retry_delays_ms: &[i64],
) -> Result<(), DeliveryError> {
    let expected_delays = usize::try_from(deployed_maximum_attempts.saturating_sub(1))
        .map_err(|_| DeliveryError::Unavailable)?;
    if !(100..=10_000).contains(&deployed_attempt_timeout_ms)
        || !(1..=20).contains(&deployed_maximum_attempts)
        || retry_delays_ms.len() < expected_delays
        || retry_delays_ms
            .iter()
            .any(|delay| !(100..=3_600_000).contains(delay))
    {
        return Err(DeliveryError::Unavailable);
    }
    Ok(())
}

/// The delivery idempotency key for one attempt: the product's domain, then
/// the length-prefixed attempt identity, digested. Stable across retries of
/// one attempt and changed by a new generation.
fn delivery_idempotency_key(
    idempotency_domain: &[u8],
    event_id: Uuid,
    compiled_delivery_id: &str,
    generation: i64,
    payload_digest: &[u8],
    destination_binding_digest: &str,
) -> String {
    idempotency_key(
        idempotency_domain,
        &[
            event_id.to_string().as_bytes(),
            compiled_delivery_id.as_bytes(),
            generation.to_string().as_bytes(),
            payload_digest,
            destination_binding_digest.as_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use registry_platform_httputil::destination::{
        DestinationRequestError, EventDestinationRequest,
    };

    use tokio_postgres::Transaction;

    use super::*;
    use crate::delivery::{
        DeliveryAuditRecord, DeliveryConnection, DeliverySignatureRefused, DeliveryTransitionCode,
    };

    // A destination the tests below never reach: it exists only so the seam
    // fixtures can name their associated destination type.
    #[derive(Clone, Copy, Debug)]
    struct UnusedDestination;

    #[async_trait::async_trait]
    impl HookDestination for UnusedDestination {
        fn binding_digest(&self) -> &str {
            ""
        }

        fn attempt_timeout(&self) -> Duration {
            Duration::ZERO
        }

        fn maximum_attempts(&self) -> u8 {
            1
        }

        fn sign_delivery(
            &self,
            _fields: DeliverySignatureFields<'_>,
        ) -> Result<String, DeliverySignatureRefused> {
            Err(DeliverySignatureRefused)
        }

        fn render_delivery(
            &self,
            _headers: EventDeliveryHeaders<'_>,
            _body: Vec<u8>,
        ) -> Result<EventDestinationRequest, DestinationRequestError> {
            unreachable!("no test below reaches a destination")
        }

        async fn send_delivery(
            &self,
            _request: EventDestinationRequest,
            _remaining: Duration,
        ) -> Result<DestinationAnswer, DestinationSendError> {
            unreachable!("no test below reaches a destination")
        }
    }

    /// A handler no test below resolves: the seams under test refuse every
    /// binding, so nothing ever runs.
    struct UnusedHandler;

    #[async_trait::async_trait]
    impl HookHandler for UnusedHandler {
        fn handler_digest(&self) -> &str {
            ""
        }

        fn attempt_timeout(&self) -> Duration {
            Duration::ZERO
        }

        fn maximum_attempts(&self) -> u8 {
            1
        }

        async fn run(
            &self,
            _envelope: &[u8],
            _remaining: Duration,
        ) -> Result<Vec<u8>, crate::delivery::HandlerRunFailure> {
            unreachable!("no test below reaches a handler")
        }
    }

    /// A seam set that refuses every connection and records every
    /// operational event it is given.
    struct RefusingSeams {
        events: Arc<Mutex<Vec<DeliveryOperationalEvent>>>,
    }

    #[async_trait::async_trait]
    impl DeliverySeams for RefusingSeams {
        type Destination = UnusedDestination;
        type Handler = UnusedHandler;

        async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn verify_transaction(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn destination(&self, _logical_destination_id: &str) -> Option<Self::Destination> {
            None
        }

        fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
            None
        }

        async fn record_audit(
            &self,
            _transaction: &Transaction<'_>,
            _record: DeliveryAuditRecord<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn operational_event(&self, event: DeliveryOperationalEvent) {
            self.events.lock().expect("events lock").push(event);
        }

        async fn apply_proposal(
            &self,
            _application: ProposalApplication<'_>,
        ) -> Result<ProposalOutcome, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt(
            &self,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt_in_transaction(
            &self,
            _transaction: &Transaction<'_>,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }
    }

    const STORED_EVENT_ID: &str = "4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51";
    const STORED_SOURCE: &str = "urn:registrystack:test:instance:hooks-delivery";
    const STORED_DATA_SCHEMA: &str = "urn:test:event-schema:permit.granted";

    fn stored_envelope() -> HookEnvelope {
        HookEnvelope {
            id: STORED_EVENT_ID.to_owned(),
            event_type: "permit.granted".to_owned(),
            source: STORED_SOURCE.to_owned(),
            time: OffsetDateTime::from_unix_timestamp_nanos(1_767_225_600_123_000_000)
                .expect("capture instant"),
            subject: crate::EventSubject {
                record_reference:
                    "8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7".to_owned(),
                record_revision: 3,
            },
            dataschema: STORED_DATA_SCHEMA.to_owned(),
            data: serde_json::json!({ "values": { "status": "granted" } }),
            causation: crate::Causation::root(STORED_EVENT_ID),
        }
    }

    fn stored_binding<'a>(body: &'a [u8], digest: &'a [u8]) -> StoredEnvelope<'a> {
        StoredEnvelope {
            event_id: Uuid::parse_str(STORED_EVENT_ID).expect("event id"),
            event_type: "permit.granted",
            source: STORED_SOURCE,
            data_schema: STORED_DATA_SCHEMA,
            event_time: SystemTime::UNIX_EPOCH + Duration::from_millis(1_767_225_600_123),
            maximum_payload_bytes: i64::try_from(body.len()).expect("bound"),
            payload_digest: digest,
        }
    }

    #[test]
    fn the_worker_accepts_the_stored_envelope_it_will_deliver_unchanged() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_ok(),
            "the stored envelope matches the delivery row that governs it"
        );
    }

    #[test]
    fn the_worker_refuses_a_body_that_is_not_an_envelope() {
        let body = br#"{"entity":"permit","recordId":"8f14e45f","revision":3}"#.to_vec();
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "a stored body in the pre-envelope shape is refused, never delivered"
        );
    }

    #[test]
    fn the_worker_refuses_an_envelope_that_disagrees_with_its_delivery_row() {
        let mut envelope = stored_envelope();
        envelope.source = "urn:registrystack:test:instance:other".to_owned();
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "an envelope whose source differs from the header the worker would sign is refused"
        );

        let mut envelope = stored_envelope();
        envelope.time += Duration::from_millis(1);
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "an envelope whose time differs from the stored capture instant is refused"
        );
    }

    #[test]
    fn the_per_delivery_bound_measures_the_whole_stored_envelope() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        let data_bytes = serde_json::to_vec(&stored_envelope().data).expect("data bytes");
        assert!(data_bytes.len() < body.len());
        let mut binding = stored_binding(&body, &digest);
        binding.maximum_payload_bytes = i64::try_from(body.len() - 1).expect("bound");
        assert!(
            accept_stored_envelope(&body, &binding).is_err(),
            "the bound refuses envelope bytes, not the product projection alone"
        );
    }

    #[test]
    fn the_worker_refuses_an_envelope_whose_captured_digest_does_not_match() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(b"other bytes").to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "the captured payload digest still pins the bytes the idempotency key is built from"
        );
    }

    #[test]
    fn attempt_budget_is_unspent_when_the_claim_clock_runs_ahead_of_this_process() {
        let attempt_timeout = Duration::from_millis(2_000);
        let attempt_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ahead_of_this_process = attempt_started_at - Duration::from_millis(5);
        assert_eq!(
            remaining_attempt_budget(attempt_timeout, attempt_started_at, ahead_of_this_process),
            Some(attempt_timeout),
            "a claim that appears to start in the local future has spent none of its budget"
        );
    }

    #[test]
    fn attempt_budget_is_exhausted_once_the_captured_attempt_timeout_elapses() {
        let attempt_timeout = Duration::from_millis(2_000);
        let attempt_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                attempt_started_at,
                attempt_started_at + Duration::from_millis(1_500)
            ),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                attempt_started_at,
                attempt_started_at + Duration::from_millis(2_001)
            ),
            None,
            "an attempt that outlives its captured timeout never reaches the destination"
        );
    }

    #[test]
    fn idempotency_key_is_stable_across_retries_and_changes_on_replay_generation() {
        let domain = b"hooks-delivery-idempotency-v1";
        let event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixture UUID parses");
        let digest = Sha256::digest(br#"{"label":"value"}"#);
        let first_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let repeated_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let replay_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            2,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(first_key, repeated_key);
        assert_ne!(first_key, replay_key);
        assert!(first_key.starts_with("sha256:"));
        assert_eq!(first_key.len(), 71);
    }

    #[test]
    fn the_idempotency_key_is_bound_to_its_configured_domain() {
        let event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixture UUID parses");
        let digest = Sha256::digest(br#"{"label":"value"}"#);
        let binding = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let one = delivery_idempotency_key(
            b"hooks-delivery-idempotency-v1",
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            binding,
        );
        let other = delivery_idempotency_key(
            b"another-product-idempotency-v1",
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            binding,
        );
        assert_ne!(
            one, other,
            "two products never share a delivery idempotency key"
        );
    }

    #[test]
    fn transport_failure_is_separate_from_a_reached_attempt_deadline() {
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, false),
            DeliveryAuditOutcome::DestinationTransportUnavailable
        );
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, true),
            DeliveryAuditOutcome::DestinationTimeout
        );
        assert_eq!(
            classify_send_error(DestinationSendError::DeadlineExceeded, false),
            DeliveryAuditOutcome::DestinationTimeout
        );
    }

    #[test]
    fn failures_after_connect_keep_the_outcome_of_their_pre_connect_counterpart() {
        for deadline_reached in [false, true] {
            assert_eq!(
                classify_send_error(
                    DestinationSendError::TransportFailedAfterConnect,
                    deadline_reached
                ),
                classify_send_error(DestinationSendError::TransportFailed, deadline_reached)
            );
            assert_eq!(
                classify_send_error(
                    DestinationSendError::DeadlineExceededAfterConnect,
                    deadline_reached
                ),
                classify_send_error(DestinationSendError::DeadlineExceeded, deadline_reached)
            );
        }
    }

    #[test]
    fn captured_policy_bounds_are_enforced_exactly() {
        let delays = [1_000, 2_000];
        assert!(validate_captured_policy(100, 1, &[]).is_ok());
        assert!(validate_captured_policy(10_000, 3, &delays).is_ok());
        assert!(validate_captured_policy(99, 1, &[]).is_err());
        assert!(validate_captured_policy(10_001, 1, &[]).is_err());
        assert!(validate_captured_policy(100, 0, &[]).is_err());
        assert!(validate_captured_policy(100, 21, &[]).is_err());
        assert!(
            validate_captured_policy(100, 2, &[99]).is_err(),
            "a delay below the floor is refused"
        );
        assert!(
            validate_captured_policy(100, 3, &[1_000]).is_err(),
            "a shortened delay list is refused"
        );
    }

    #[test]
    fn the_operator_status_reflects_payload_expiry_on_pending_rows() {
        assert_eq!(
            delivery_status_kind("pending", true),
            Ok(DeliveryStatusKind::Pending)
        );
        assert_eq!(
            delivery_status_kind("pending", false),
            Ok(DeliveryStatusKind::Expired)
        );
        assert_eq!(
            delivery_status_kind("expired", false),
            Ok(DeliveryStatusKind::Expired)
        );
        assert_eq!(
            delivery_status_kind("dead_lettered", false),
            Ok(DeliveryStatusKind::DeadLettered)
        );
        assert_eq!(
            delivery_status_kind("leased", true),
            Err(DeliveryError::Unavailable)
        );
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn a_service_refuses_a_schema_that_is_not_a_plain_identifier() {
        let seams = RefusingSeams {
            events: Arc::new(Mutex::new(Vec::new())),
        };
        let _ = DeliveryService::new(
            seams,
            DeliveryConfig {
                schema: "registry; drop table users".to_owned(),
                idempotency_domain: b"hooks-delivery-refusal-test-v1".to_vec(),
                delivery_source: "urn:registrystack:test:instance:hooks-delivery".to_owned(),
            },
        );
    }

    #[tokio::test]
    async fn the_worker_loop_reports_iteration_failures_and_stops_on_shutdown() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = DeliveryService::new(
            RefusingSeams {
                events: Arc::clone(&events),
            },
            DeliveryConfig {
                schema: "hooks_delivery_loop_test".to_owned(),
                idempotency_domain: b"hooks-delivery-loop-test-v1".to_vec(),
                delivery_source: "urn:registrystack:test:instance:hooks-delivery".to_owned(),
            },
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(DeliveryWorker::new(service).run(shutdown_rx));
        tokio::time::sleep(Duration::from_millis(250)).await;
        shutdown_tx
            .send(true)
            .expect("the shutdown receiver is alive");
        handle.await.expect("the worker task joins");
        let recorded = events.lock().expect("events lock");
        assert!(
            recorded.contains(&DeliveryOperationalEvent::IterationFailed),
            "a failed iteration is reported through the operational seam"
        );
        assert!(
            recorded.iter().all(|event| *event
                != DeliveryOperationalEvent::TransitionFailed(
                    DeliveryTransitionCode::ClaimIdentityRefused
                )),
            "a failure before the claim transaction emits no transition code"
        );
    }
    #[test]
    fn an_empty_answer_body_reads_as_the_none_answer() {
        let accepted = accept_handler_answer(b"").expect("an empty body is the none answer");
        assert_eq!(
            accepted.bytes,
            br#"{"answer":"none"}"#.to_vec(),
            "an empty body is recorded as the canonical none answer"
        );
    }

    #[test]
    fn an_answer_over_the_output_ceiling_is_a_resource_failure() {
        let mut body = br#"{"answer":"proposal","document":{"padding":""#.to_vec();
        body.resize(body.len() + crate::MAX_OUTPUT_BYTES, b'x');
        body.extend_from_slice(br#""}}"#);
        assert_eq!(
            accept_handler_answer(&body).expect_err("an oversize answer is refused"),
            ErrorCategory::Resource,
            "a body over the ceiling is a resource failure"
        );
    }

    #[test]
    fn a_malformed_answer_is_a_source_failure() {
        assert_eq!(
            accept_handler_answer(b"not json").expect_err("a malformed answer is refused"),
            ErrorCategory::Source,
            "a body that is not the handler message is a source failure"
        );
        assert_eq!(
            accept_handler_answer(br#"{"answer":"maybe"}"#)
                .expect_err("an unknown answer is refused"),
            ErrorCategory::Source,
            "a body outside the closed answer vocabulary is a source failure"
        );
    }

    #[test]
    fn a_non_canonical_answer_is_a_source_failure() {
        assert_eq!(
            accept_handler_answer(br#"{"answer": "none"}"#)
                .expect_err("a non-canonical answer is refused"),
            ErrorCategory::Source,
            "a body that is not its own canonicalization is a source failure"
        );
    }

    #[test]
    fn the_recorded_answer_digest_covers_the_canonical_message_bytes() {
        let body =
            br#"{"answer":"refusal","code":"permit.expired","summary":"The permit lapsed."}"#;
        let accepted = accept_handler_answer(body).expect("a refusal answer is accepted");
        assert_eq!(
            accepted.bytes,
            body.to_vec(),
            "the recorded message is the canonical answer the handler produced"
        );
        assert_eq!(
            accepted.digest.to_vec(),
            Sha256::digest(body).to_vec(),
            "the recorded digest covers exactly the recorded message bytes"
        );
    }

    /// A seam set that records every proposal it is handed and answers with a
    /// programmed outcome. Every method the delivery path before the apply
    /// step uses still refuses, so nothing but the apply seam is reachable.
    struct ProposalSeams {
        applications: Arc<Mutex<Vec<RecordedApplication>>>,
        recoveries: Arc<Mutex<Vec<RecordedRecovery>>>,
        answer: Result<ProposalOutcome, DeliveryError>,
        recovery: Result<Option<ProposalOutcome>, DeliveryError>,
    }

    struct RecordedApplication {
        event_id: Uuid,
        compiled_delivery_id: String,
        package_revision: String,
        envelope: Vec<u8>,
        answer: Vec<u8>,
        answer_digest: [u8; 32],
    }

    struct RecordedRecovery {
        event_id: Uuid,
        compiled_delivery_id: String,
    }

    #[async_trait::async_trait]
    impl DeliverySeams for ProposalSeams {
        type Destination = UnusedDestination;
        type Handler = UnusedHandler;

        async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn verify_transaction(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn destination(&self, _logical_destination_id: &str) -> Option<Self::Destination> {
            None
        }

        fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
            None
        }

        async fn record_audit(
            &self,
            _transaction: &Transaction<'_>,
            _record: DeliveryAuditRecord<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn operational_event(&self, _event: DeliveryOperationalEvent) {}

        async fn apply_proposal(
            &self,
            application: ProposalApplication<'_>,
        ) -> Result<ProposalOutcome, DeliveryError> {
            self.applications
                .lock()
                .expect("applications lock")
                .push(RecordedApplication {
                    event_id: application.event_id,
                    compiled_delivery_id: application.compiled_delivery_id.to_owned(),
                    package_revision: application.package_revision.to_owned(),
                    envelope: application.envelope.to_vec(),
                    answer: application.answer.to_vec(),
                    answer_digest: *application.answer_digest,
                });
            self.answer.clone()
        }

        async fn recover_proposal_receipt(
            &self,
            recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            self.recoveries
                .lock()
                .expect("recoveries lock")
                .push(RecordedRecovery {
                    event_id: recovery.event_id,
                    compiled_delivery_id: recovery.compiled_delivery_id.to_owned(),
                });
            self.recovery.clone()
        }

        async fn recover_proposal_receipt_in_transaction(
            &self,
            _transaction: &Transaction<'_>,
            recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            self.recoveries
                .lock()
                .expect("recoveries lock")
                .push(RecordedRecovery {
                    event_id: recovery.event_id,
                    compiled_delivery_id: recovery.compiled_delivery_id.to_owned(),
                });
            self.recovery.clone()
        }
    }

    fn proposal_claim() -> DeliveryClaim {
        DeliveryClaim {
            event_id: Uuid::parse_str(STORED_EVENT_ID).expect("event id"),
            compiled_delivery_id: "events.permit.granted.webhook".to_owned(),
            generation: 1,
            attempt: 1,
            attempt_started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            lease_token: Uuid::new_v4(),
            deployed_maximum_attempts: 2,
            package_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            handler_kind: HookHandlerKind::Rhai,
        }
    }

    fn proposal_service(
        applications: Arc<Mutex<Vec<RecordedApplication>>>,
        recoveries: Arc<Mutex<Vec<RecordedRecovery>>>,
        answer: Result<ProposalOutcome, DeliveryError>,
        recovery: Result<Option<ProposalOutcome>, DeliveryError>,
    ) -> DeliveryService<ProposalSeams> {
        DeliveryService::new(
            ProposalSeams {
                applications,
                recoveries,
                answer,
                recovery,
            },
            DeliveryConfig {
                schema: "hooks_delivery_proposal_test".to_owned(),
                idempotency_domain: b"hooks-delivery-proposal-test-v1".to_vec(),
                delivery_source: STORED_SOURCE.to_owned(),
            },
        )
    }

    fn stored_envelope_bytes() -> Vec<u8> {
        stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes")
    }

    #[tokio::test]
    async fn an_accepted_proposal_is_handed_to_the_product_seam() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Ok(ProposalOutcome::Applied {
                resulting_revision: 7,
            }),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        let answer = br#"{"answer":"proposal","document":{"kind":"action-outcome"}}"#;
        let settled = service
            .settle_answer(&claim, &envelope, accepted_answer_result(answer))
            .await
            .expect("the apply seam answers");
        assert!(matches!(
            settled.proposal,
            Some(ProposalOutcome::Applied {
                resulting_revision: 7
            })
        ));
        let recorded = applications.lock().expect("applications lock");
        assert_eq!(recorded.len(), 1, "exactly one application per proposal");
        assert_eq!(recorded[0].event_id, claim.event_id);
        assert_eq!(recorded[0].compiled_delivery_id, claim.compiled_delivery_id);
        assert_eq!(recorded[0].package_revision, claim.package_revision);
        assert_eq!(recorded[0].envelope, envelope);
        assert_eq!(recorded[0].answer, answer.to_vec());
        let expected_digest: [u8; 32] = Sha256::digest(answer).into();
        assert_eq!(
            recorded[0].answer_digest, expected_digest,
            "the application identity is the digest of exactly the recorded answer bytes"
        );
    }

    #[tokio::test]
    async fn an_uncertain_apply_fails_closed_before_any_finalization() {
        // The seam's error means the apply may have committed and the worker
        // cannot know: the attempt result must not become a delivered row, so
        // the error propagates and the lease is left for expiry recovery.
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Err(DeliveryError::Unavailable),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        let answer = br#"{"answer":"proposal","document":{"kind":"action-outcome"}}"#;
        let settled = service
            .settle_answer(&claim, &envelope, accepted_answer_result(answer))
            .await;
        assert!(
            matches!(settled, Err(DeliveryError::Unavailable)),
            "an uncertain apply never reaches finalize as a settled outcome"
        );
        assert_eq!(
            applications.lock().expect("applications lock").len(),
            1,
            "the seam was asked exactly once before the uncertainty"
        );
    }

    #[tokio::test]
    async fn an_answer_that_proposes_nothing_checks_only_for_a_committed_proposal() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Ok(ProposalOutcome::Applied {
                resulting_revision: 7,
            }),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        for body in [
            b"".as_slice(),
            br#"{"answer":"none"}"#.as_slice(),
            br#"{"answer":"refusal","code":"permit.expired","summary":"The permit lapsed."}"#
                .as_slice(),
        ] {
            let settled = service
                .settle_answer(&claim, &envelope, accepted_answer_result(body))
                .await
                .expect("an answer without a proposal checks for an earlier receipt");
            assert!(
                settled.proposal.is_none(),
                "a none or refusal answer carries no proposal to apply"
            );
        }
        assert!(
            applications.lock().expect("applications lock").is_empty(),
            "the apply seam is only asked for a proposal answer"
        );
        let recoveries = recoveries.lock().expect("recoveries lock");
        assert_eq!(recoveries.len(), 3);
        assert!(recoveries.iter().all(|recovery| {
            recovery.event_id == claim.event_id
                && recovery.compiled_delivery_id == claim.compiled_delivery_id
        }));
    }

    #[tokio::test]
    async fn a_non_proposal_answer_keeps_a_recovered_proposal_conflict() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let conflict = ProposalOutcome::DeadLettered {
            code: crate::BoundedText::try_from("hook.proposal.answer_conflict")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from(
                "This delivery already applied a different answer; the first application stands.",
            )
            .expect("within the summary bound"),
        };
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Err(DeliveryError::Unavailable),
            Ok(Some(conflict.clone())),
        );
        let claim = proposal_claim();
        let settled = service
            .settle_answer(
                &claim,
                &stored_envelope_bytes(),
                accepted_answer_result(br#"{"answer":"none"}"#),
            )
            .await
            .expect("the committed proposal receipt settles the changed answer");
        assert_eq!(settled.proposal, Some(conflict));
        assert!(applications.lock().expect("applications lock").is_empty());
        assert_eq!(recoveries.lock().expect("recoveries lock").len(), 1);
    }

    #[test]
    fn the_terminal_transition_writes_the_disposition_it_earned() {
        let applied = ProposalOutcome::Applied {
            resulting_revision: 3,
        };
        let refused = ProposalOutcome::Refused {
            code: crate::BoundedText::try_from("hook.proposal.outcome_refused")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from("the proposal failed validation")
                .expect("within the summary bound"),
        };
        let dead_lettered = ProposalOutcome::DeadLettered {
            code: crate::BoundedText::try_from("hook.proposal.no_principal")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from("the hook declares no principal")
                .expect("within the summary bound"),
        };

        let none = proposal_columns("delivered", None).expect("delivered always states one");
        assert_eq!(none.disposition, Some("none"));
        assert_eq!(none.resulting_revision, None);
        assert_eq!(none.code, None);
        assert_eq!(none.summary, None);

        let applied_columns =
            proposal_columns("delivered", Some(&applied)).expect("applied is recorded");
        assert_eq!(applied_columns.disposition, Some("applied"));
        assert_eq!(applied_columns.resulting_revision, Some(3));
        assert_eq!(applied_columns.code, None);
        assert_eq!(applied_columns.summary, None);

        let refused_columns =
            proposal_columns("delivered", Some(&refused)).expect("a refusal is recorded");
        assert_eq!(refused_columns.disposition, Some("refused"));
        assert_eq!(refused_columns.resulting_revision, None);
        assert_eq!(refused_columns.code, Some("hook.proposal.outcome_refused"));
        assert_eq!(
            refused_columns.summary,
            Some("the proposal failed validation")
        );

        let dead_columns = proposal_columns("dead_lettered", Some(&dead_lettered))
            .expect("a dead-lettered proposal is recorded");
        assert_eq!(dead_columns.disposition, Some("dead_lettered"));
        assert_eq!(dead_columns.resulting_revision, None);
        assert_eq!(dead_columns.code, Some("hook.proposal.no_principal"));
        assert_eq!(dead_columns.summary, Some("the hook declares no principal"));

        // A row that dead-letters without accepting an answer keeps the
        // legacy all-null shape: it never had a proposal to settle.
        let exhausted = proposal_columns("dead_lettered", None).expect("legacy shape holds");
        assert_eq!(exhausted.disposition, None);
        assert_eq!(exhausted.resulting_revision, None);
        assert_eq!(exhausted.code, None);
        assert_eq!(exhausted.summary, None);
    }
}
