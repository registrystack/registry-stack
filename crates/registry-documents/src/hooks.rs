// SPDX-License-Identifier: Apache-2.0

//! The Document Store's closed after-commit observer runtime.
//!
//! The shared hook crate owns the envelope and the delivery state machine.
//! This module owns the Document Store's policy: three triggers, a
//! projection each hook chooses from its trigger's closed fields, URL
//! handlers only, exact deployment destination activation, and a worker that
//! can observe an answer but never apply a proposal.
//!
//! A capture runs inside the transaction that makes the change it reports,
//! so a transition that rolls back leaves no event, and one that commits
//! leaves exactly one delivery per matching hook. Delivery happens after
//! commit; a destination that is down, slow, or refusing never holds back
//! the transition.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};

use registry_documents_core::{
    ActorKind, DocumentsProject, HookTrigger, DOCUMENTS_EVENT_SOURCE_PREFIX,
    DOCUMENT_GRANT_EVENT_FIELDS,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{
    SecretResolver, UrlHookDestinationConfig, MAX_HOOK_ATTEMPTS,
    MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use registry_platform_hooks::delivery::{
    activate_url_hook_destinations, hook_audit_entry, insert_delivery, verify_active_package,
    ActivatedUrlHookDestinations, DeliveryAuditRecord, DeliveryCapture, DeliveryConfig,
    DeliveryConnection, DeliveryError, DeliveryOperationalEvent, DeliveryOutcome, DeliverySeams,
    DeliveryService, DeliveryWorker, HookHandlerBinding, NoLocalHandler, PooledConnection,
    ProposalApplication, ProposalOutcome, ProposalReceiptRecovery, SharedUrlDestination,
    UrlHookActivationError,
};
use registry_platform_hooks::{
    exponential_retry_delays_ms, validate_hooks, BoundedText, Causation, EnvelopeLimits,
    EventSubject, HookCapabilities, HookCapability, HookCapabilityError, HookDeclaration,
    HookEnvelope, HookHandlerKind, HookHandlerSource, HookPhase, MAX_REFUSAL_CODE_BYTES,
    MAX_REFUSAL_SUMMARY_BYTES,
};
use registry_platform_httputil::destination::MAX_DESTINATION_REQUEST_BODY_BYTES;
use registry_platform_yaml::LocalId;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::activation;
use crate::audit::{DocumentsAudit, DOCUMENTS_AUDIT_SCHEMA, HOOK_DELIVERY_EVENT};
use crate::store::PostgresStore;

const DESTINATION_BINDING_SCHEMA: &str = "registry.documents-hook-destinations/v1";
const COMPILED_HOOK_SCHEMA: &str = "registry.documents-hooks/v1";
const IDEMPOTENCY_DOMAIN: &[u8] = b"documents-hook-idempotency-v1";
/// The refusal code retained with a delivery whose destination answered with
/// a proposal. Each dotted segment is lowercase kebab-case.
const PROPOSAL_UNSUPPORTED_CODE: &str = "documents.hook.proposal-unsupported";

const INITIAL_BACKOFF_MS: u32 = 30_000;
const MAXIMUM_BACKOFF_MS: u32 = 3_600_000;
const BACKOFF_MULTIPLIER: u8 = 2;
const MAXIMUM_PAYLOAD_BYTES: usize = 16 * 1024;
const IDENTITY_LOCK_TIMEOUT_MS: u32 = 5_000;
const MINIMUM_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAXIMUM_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const _: () = assert!(MAXIMUM_PAYLOAD_BYTES <= MAX_DESTINATION_REQUEST_BODY_BYTES);

/// Value-free refusal from hook compilation or deployment activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HookActivationError {
    #[error("the Document Store hook declaration is invalid")]
    InvalidDeclaration,
    #[error("the Document Store hook contract is unsupported")]
    UnsupportedContract,
    /// A declaration uses a part of the shared hook declaration outside the
    /// url-only capabilities the Document Store runs. The message leads with
    /// the shared `hook.capability.unsupported` code.
    #[error(
        "{}: Document Store hook {index} uses `{}`, outside the url-only hook capabilities the Document Store runs",
        HookCapabilityError::CODE,
        capability.as_str()
    )]
    UnsupportedCapability {
        index: usize,
        capability: HookCapability,
    },
    #[error("destinations.hooks does not bind every destination documents.yaml hooks name")]
    DestinationInventoryMismatch,
    #[error("a Document Store hook destination binding is invalid")]
    InvalidDestination,
    #[error("a Document Store hook destination widens the fixed delivery budget")]
    DeliveryBudgetWidening,
    #[error("a Document Store hook signing secret is unavailable or invalid")]
    InvalidSigningMaterial,
    #[error("the Document Store hook runtime identity is invalid")]
    InvalidIdentity,
}

impl HookActivationError {
    /// The shared diagnostic code a refusal carries, when it has one.
    #[must_use]
    pub const fn code(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedCapability { .. } => Some(HookCapabilityError::CODE),
            _ => None,
        }
    }
}

impl From<HookCapabilityError> for HookActivationError {
    fn from(error: HookCapabilityError) -> Self {
        Self::UnsupportedCapability {
            index: error.index,
            capability: error.capability,
        }
    }
}

/// Value-free refusal while capturing a committed document event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HookCaptureError {
    #[error("the Document Store hook capture is invalid")]
    InvalidCapture,
    #[error("the Document Store hook outbox is unavailable")]
    Unavailable,
}

/// The deployment a hook runtime serves: the project id names the event
/// source, the package digest is the revision every captured delivery
/// records, and the database id with that digest is what the activation
/// ledger must still name before any delivery leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookRuntimeIdentity {
    pub project_id: String,
    pub package_digest: String,
    pub database_id: String,
}

/// Whether a grant event reports an issue or a revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantChange {
    Issued,
    Revoked,
}

impl GrantChange {
    /// The `change` value an observer receives.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Revoked => "revoked",
        }
    }
}

/// What a grant event reports about the grant itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantFacts {
    pub grant_id: Uuid,
    pub change: GrantChange,
    /// The kind of the caller that issued or revoked the grant.
    pub actor_kind: ActorKind,
    /// The expiry frozen into the grant at issue. Reaching it is not a
    /// recorded transition and emits no event.
    pub expires_at: DateTime<Utc>,
}

/// Everything an observer of one event may be told, read from the store
/// inside the transaction that made the change. Nothing else about the
/// document, its content, its parties, or the request is held here, so no
/// projection can reach it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentEvent {
    pub trigger: HookTrigger,
    pub document_id: Uuid,
    pub version_id: Uuid,
    pub version_digest: String,
    pub policy_id: String,
    pub policy_version: String,
    /// The revision the change leaves the reported record at: the
    /// version's on a version event, the grant's on a grant event. Every
    /// recorded change of state advances it, so it only grows.
    pub revision: i64,
    /// Present exactly on a grant event.
    pub grant: Option<GrantFacts>,
}

impl DocumentEvent {
    /// The version event `trigger` reports for `version_id`, read under the
    /// row lock the transition holds.
    pub async fn version(
        transaction: &Transaction<'_>,
        trigger: HookTrigger,
        version_id: Uuid,
    ) -> Result<Self, HookCaptureError> {
        if trigger == HookTrigger::DocumentGrantChanged {
            return Err(HookCaptureError::InvalidCapture);
        }
        let row = transaction
            .query_one(
                "SELECT document.document_id, version.version_id,
                        COALESCE(version.verified_digest, version.computed_digest,
                                 version.expected_digest),
                        document.policy_id, document.policy_version, version.revision
                   FROM documents_versions AS version
                   JOIN documents_documents AS document
                     ON document.document_id = version.document_id
                  WHERE version.version_id = $1",
                &[&version_id],
            )
            .await
            .map_err(|_| HookCaptureError::Unavailable)?;
        Self::from_row(&row, trigger, None)
    }

    /// The grant event `change` reports for `grant_id`, made by a caller of
    /// `actor_kind`, read under the row lock the transition holds.
    pub async fn grant(
        transaction: &Transaction<'_>,
        grant_id: Uuid,
        change: GrantChange,
        actor_kind: ActorKind,
    ) -> Result<Self, HookCaptureError> {
        let row = transaction
            .query_one(
                "SELECT document.document_id, version.version_id,
                        COALESCE(version.verified_digest, version.computed_digest,
                                 version.expected_digest),
                        document.policy_id, document.policy_version, grant_record.revision,
                        grant_record.expires_at
                   FROM documents_grants AS grant_record
                   JOIN documents_versions AS version
                     ON version.version_id = grant_record.version_id
                   JOIN documents_documents AS document
                     ON document.document_id = grant_record.document_id
                  WHERE grant_record.grant_id = $1",
                &[&grant_id],
            )
            .await
            .map_err(|_| HookCaptureError::Unavailable)?;
        let expires_at = row.try_get(6).map_err(|_| HookCaptureError::Unavailable)?;
        Self::from_row(
            &row,
            HookTrigger::DocumentGrantChanged,
            Some(GrantFacts {
                grant_id,
                change,
                actor_kind,
                expires_at,
            }),
        )
    }

    fn from_row(
        row: &tokio_postgres::Row,
        trigger: HookTrigger,
        grant: Option<GrantFacts>,
    ) -> Result<Self, HookCaptureError> {
        let column = |index: usize| {
            row.try_get::<_, String>(index)
                .map_err(|_| HookCaptureError::Unavailable)
        };
        let revision: i64 = row.try_get(5).map_err(|_| HookCaptureError::Unavailable)?;
        if revision < 1 {
            return Err(HookCaptureError::InvalidCapture);
        }
        Ok(Self {
            trigger,
            document_id: row.try_get(0).map_err(|_| HookCaptureError::Unavailable)?,
            version_id: row.try_get(1).map_err(|_| HookCaptureError::Unavailable)?,
            version_digest: column(2)?,
            policy_id: column(3)?,
            policy_version: column(4)?,
            revision,
            grant,
        })
    }

    /// The record the event is about and the revision the change leaves it
    /// at.
    fn subject(&self) -> Result<EventSubject, HookCaptureError> {
        let record_reference = match (self.trigger, &self.grant) {
            (HookTrigger::DocumentGrantChanged, Some(grant)) => {
                format!("/document-grants/{}", grant.grant_id)
            }
            (HookTrigger::DocumentVersionReady | HookTrigger::DocumentVersionRejected, None) => {
                format!(
                    "/documents/{}/versions/{}",
                    self.document_id, self.version_id
                )
            }
            _ => return Err(HookCaptureError::InvalidCapture),
        };
        Ok(EventSubject {
            record_reference,
            record_revision: self.revision,
        })
    }
}

/// One observer declaration and the document policies it is scoped to.
/// The shared declaration has no place for the scope, so it travels beside
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedHook {
    pub declaration: HookDeclaration,
    /// The policies whose documents the observer hears about, at least one.
    pub policies: Vec<String>,
}

impl ScopedHook {
    /// The scoped declarations of every hook `project` declares, in
    /// declaration order.
    #[must_use]
    pub fn of(project: &DocumentsProject) -> Vec<Self> {
        project
            .hooks
            .iter()
            .map(|hook| Self {
                declaration: hook.declaration(),
                policies: hook
                    .policies
                    .as_slice()
                    .iter()
                    .map(|policy| policy.as_str().to_owned())
                    .collect(),
            })
            .collect()
    }
}

/// Validated and compiled Document Store observer declarations.
#[derive(Clone, Debug)]
pub struct CompiledHooks {
    hooks: Vec<CompiledHook>,
    destination_ids: BTreeSet<String>,
    schema_fingerprint: String,
}

#[derive(Clone, Debug)]
struct CompiledHook {
    id: String,
    trigger: HookTrigger,
    projection: Vec<String>,
    policies: BTreeSet<String>,
    destination_id: String,
}

impl CompiledHooks {
    /// Compile the shared declaration shape into the Document Store's closed
    /// observer contract. The authored project was checked when it was
    /// read; compiling again here means no unchecked declaration reaches
    /// capture.
    pub fn compile(scoped: &[ScopedHook]) -> Result<Self, HookActivationError> {
        let declarations = scoped
            .iter()
            .map(|hook| hook.declaration.clone())
            .collect::<Vec<_>>();
        validate_hooks(&declarations).map_err(|_| HookActivationError::InvalidDeclaration)?;
        HookCapabilities::URL_ONLY.check_declarations(&declarations)?;

        let mut hooks = Vec::with_capacity(declarations.len());
        let mut destination_ids = BTreeSet::new();
        for ScopedHook {
            declaration,
            policies,
        } in scoped
        {
            let scope = policies.iter().cloned().collect::<BTreeSet<_>>();
            if scope.is_empty()
                || scope.len() != policies.len()
                || scope
                    .iter()
                    .any(|policy| LocalId::new(policy.as_str()).is_err())
            {
                return Err(HookActivationError::UnsupportedContract);
            }
            if LocalId::new(declaration.id.as_str()).is_err()
                || declaration.phase != HookPhase::After
            {
                return Err(HookActivationError::UnsupportedContract);
            }
            let destination_id = match &declaration.handler {
                HookHandlerSource::Url { destination_id }
                    if LocalId::new(destination_id.as_str()).is_ok() =>
                {
                    destination_id.clone()
                }
                _ => return Err(HookActivationError::UnsupportedContract),
            };
            let trigger = HookTrigger::from_name(&declaration.trigger)
                .ok_or(HookActivationError::UnsupportedContract)?;
            if declaration
                .projection
                .iter()
                .any(|field| !trigger.fields().contains(&field.as_str()))
            {
                return Err(HookActivationError::UnsupportedContract);
            }
            destination_ids.insert(destination_id.clone());
            hooks.push(CompiledHook {
                id: declaration.id.clone(),
                trigger,
                projection: declaration.projection.iter().cloned().collect(),
                policies: scope,
                destination_id,
            });
        }

        let fingerprint_value = json!({
            "schemaVersion": COMPILED_HOOK_SCHEMA,
            "hooks": hooks.iter().map(|hook| json!({
                "id": hook.id,
                "trigger": hook.trigger.as_str(),
                "projection": hook.projection,
                "policies": hook.policies,
                "destinationId": hook.destination_id,
                "dataSchema": hook.trigger.data_schema_id(),
            })).collect::<Vec<_>>(),
        });
        let schema_fingerprint = canonical_digest(&fingerprint_value)
            .map_err(|()| HookActivationError::InvalidDeclaration)?;
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
    destinations: Arc<ActivatedUrlHookDestinations>,
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
    /// Compile `declarations` and activate the configured destination
    /// inventory, which must bind every destination they name. Additional
    /// bindings stay available for deliveries captured under an earlier
    /// package.
    pub fn activate(
        declarations: &[ScopedHook],
        configured: &BTreeMap<String, UrlHookDestinationConfig>,
        secrets: &SecretResolver,
        identity: HookRuntimeIdentity,
        database_schema: String,
        payload_retention: Duration,
    ) -> Result<Self, HookActivationError> {
        let compiled = Arc::new(CompiledHooks::compile(declarations)?);
        validate_identity(&identity, &database_schema, payload_retention)?;
        let destinations = Arc::new(activate_destinations(
            &compiled.destination_ids,
            configured,
            secrets,
        )?);
        let delivery_source = format!("{DOCUMENTS_EVENT_SOURCE_PREFIX}{}", identity.project_id);
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

    #[must_use]
    pub fn destination_binding_digest(&self) -> &str {
        &self.destinations.binding_digest
    }

    /// Capture one canonical envelope and one delivery row for every hook on
    /// `event`'s trigger that is scoped to the policy its document is held
    /// under, in declaration order and inside the caller's transaction.
    /// Returns how many deliveries were captured.
    pub async fn capture(
        &self,
        transaction: &Transaction<'_>,
        event: &DocumentEvent,
    ) -> Result<usize, HookCaptureError> {
        let subject = event.subject()?;
        let matching = self
            .compiled
            .hooks
            .iter()
            .filter(|hook| {
                hook.trigger == event.trigger && hook.policies.contains(&event.policy_id)
            })
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

        for hook in &matching {
            let event_id = Uuid::new_v4();
            let id = event_id.to_string();
            let envelope = HookEnvelope {
                id: id.clone(),
                event_type: hook.id.clone(),
                source: self.delivery_source.clone(),
                time: created_at.into(),
                subject: subject.clone(),
                dataschema: hook.trigger.data_schema_id().to_owned(),
                data: projected(event, &hook.projection)?,
                causation: Causation::root(&id),
            };
            let payload = envelope
                .to_canonical_bytes(&EnvelopeLimits::tightened_to(MAXIMUM_PAYLOAD_BYTES))
                .map_err(|_| HookCaptureError::InvalidCapture)?;
            self.insert_outbox(
                transaction,
                event_id,
                hook,
                &subject,
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
                    package_revision: &self.identity.package_digest,
                    schema_fingerprint: &self.compiled.schema_fingerprint,
                    data_schema: hook.trigger.data_schema_id(),
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
        Ok(matching.len())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_outbox(
        &self,
        transaction: &Transaction<'_>,
        event_id: Uuid,
        hook: &CompiledHook,
        subject: &EventSubject,
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
        let entity_id = match hook.trigger {
            HookTrigger::DocumentGrantChanged => "document-grant",
            HookTrigger::DocumentVersionReady | HookTrigger::DocumentVersionRejected => {
                "document-version"
            }
        };
        let changed = transaction
            .execute(
                &sql,
                &[
                    &event_id,
                    &hook.id,
                    &hook.trigger.as_str(),
                    &entity_id,
                    &subject.record_reference,
                    &subject.record_revision,
                    &self.identity.package_digest,
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

    /// Bind the generic platform service to the Document Store's database
    /// schema, audit journal, destinations, and fixed wire constants.
    #[must_use]
    pub fn delivery_service(
        &self,
        store: PostgresStore,
        audit: DocumentsAudit,
    ) -> HookDeliveryService {
        let seams = DocumentsDeliverySeams {
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

/// Activate the configured destination inventory, which must bind every
/// destination `expected` names.
fn activate_destinations(
    expected: &BTreeSet<String>,
    configured: &BTreeMap<String, UrlHookDestinationConfig>,
    secrets: &SecretResolver,
) -> Result<ActivatedUrlHookDestinations, HookActivationError> {
    let configured_ids = configured.keys().cloned().collect::<BTreeSet<_>>();
    if !expected.is_subset(&configured_ids) {
        return Err(HookActivationError::DestinationInventoryMismatch);
    }
    activate_url_hook_destinations(
        DESTINATION_BINDING_SCHEMA,
        configured,
        secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .map_err(activation_error)
}

fn activation_error(error: UrlHookActivationError) -> HookActivationError {
    match error {
        UrlHookActivationError::DeliveryBudgetWidening => {
            HookActivationError::DeliveryBudgetWidening
        }
        UrlHookActivationError::InvalidDestination => HookActivationError::InvalidDestination,
        UrlHookActivationError::InvalidSigningMaterial => {
            HookActivationError::InvalidSigningMaterial
        }
    }
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
struct DocumentsDeliverySeams {
    store: PostgresStore,
    audit: DocumentsAudit,
    destinations: Arc<ActivatedUrlHookDestinations>,
    identity: HookRuntimeIdentity,
}

#[async_trait::async_trait]
impl DeliverySeams for DocumentsDeliverySeams {
    type Destination = SharedUrlDestination;
    type Handler = NoLocalHandler;

    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
        let client = self.store.client().await.map_err(|error| {
            tracing::error!(error = %error, "the hook delivery worker could not reach the database");
            DeliveryError::Unavailable
        })?;
        Ok(PooledConnection::boxed(client))
    }

    /// Every delivery transaction must find the package and deployment it
    /// was activated for still active in the ledger, so a worker left
    /// running after a successor activation delivers nothing.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError> {
        verify_active_package(
            transaction,
            &activation::layout(),
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
        Ok(proposal_refusal())
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

    /// One attempt's entries share a correlation built from the hook event,
    /// the compiled delivery, the generation, and the attempt. The platform
    /// worker records an attempt's start before its request can leave the
    /// process, and a terminal disposition only after it commits.
    async fn record_audit(&self, record: DeliveryAuditRecord<'_>) -> Result<(), DeliveryError> {
        let mut fields = Map::new();
        fields.insert("hookEventId".to_owned(), json!(record.event_id));
        fields.insert(
            "compiledDeliveryId".to_owned(),
            json!(record.compiled_delivery_id),
        );
        fields.insert("packageDigest".to_owned(), json!(record.package_revision));
        let correlation_base = format!(
            "{}/{}/{}/{}",
            record.event_id, record.compiled_delivery_id, record.generation, record.attempt
        );
        let entry = hook_audit_entry(
            DOCUMENTS_AUDIT_SCHEMA,
            HOOK_DELIVERY_EVENT,
            &correlation_base,
            fields,
            &record,
        )
        .map_err(|_| DeliveryError::Unavailable)?;
        self.audit.append(entry).await.map_err(|error| {
            tracing::error!(error = %error, "the hook delivery audit entry could not be written");
            DeliveryError::Unavailable
        })
    }

    fn operational_event(&self, event: DeliveryOperationalEvent) {
        match event {
            DeliveryOperationalEvent::IterationFailed => {
                tracing::warn!(event = "documents_hook_delivery_iteration_failed");
            }
            DeliveryOperationalEvent::TransitionFailed(code) => {
                tracing::warn!(
                    event = "documents_hook_delivery_transition_failed",
                    code = code.as_str()
                );
            }
        }
    }
}

/// The answer to every proposal an observer returns: the Document Store
/// applies none.
fn proposal_refusal() -> ProposalOutcome {
    ProposalOutcome::Refused {
        code: BoundedText::<MAX_REFUSAL_CODE_BYTES>::new(PROPOSAL_UNSUPPORTED_CODE.to_owned())
            .expect("the static proposal code fits its bound"),
        summary: BoundedText::<MAX_REFUSAL_SUMMARY_BYTES>::new(
            "Document Store observer hooks cannot propose changes".to_owned(),
        )
        .expect("the static proposal summary fits its bound"),
    }
}

/// The Document Store's usable wrapper around the generic delivery service.
#[derive(Clone)]
pub struct HookDeliveryService {
    inner: DeliveryService<DocumentsDeliverySeams>,
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

/// The Document Store's post-commit hook delivery loop.
pub struct HookDeliveryWorker {
    inner: DeliveryWorker<DocumentsDeliverySeams>,
}

impl HookDeliveryWorker {
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        self.inner.run(shutdown).await;
    }
}

/// The data of one event: exactly the fields `projection` names, each read
/// from the closed event facts. A field outside the trigger's closed set is
/// refused rather than dropped.
fn projected(event: &DocumentEvent, projection: &[String]) -> Result<Value, HookCaptureError> {
    let mut values = Map::new();
    for field in projection {
        if !event.trigger.fields().contains(&field.as_str()) {
            return Err(HookCaptureError::InvalidCapture);
        }
        let value = match (field.as_str(), &event.grant) {
            ("documentId", _) => json!(event.document_id),
            ("versionId", _) => json!(event.version_id),
            ("versionDigest", _) => json!(event.version_digest),
            ("policyId", _) => json!(event.policy_id),
            ("policyVersion", _) => json!(event.policy_version),
            ("actorKind", Some(grant)) => json!(grant.actor_kind.as_str()),
            ("grantId", Some(grant)) => json!(grant.grant_id),
            ("change", Some(grant)) => json!(grant.change.as_str()),
            ("expiresAt", Some(grant)) => json!(grant
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Millis, true)),
            // Content, labels, media types, names, subjects, recipients,
            // and anything about the person a document describes are not
            // representable here.
            _ => return Err(HookCaptureError::InvalidCapture),
        };
        values.insert(field.clone(), value);
    }
    Ok(Value::Object(values))
}

/// The published JSON Schema of the data every event of `trigger` carries:
/// a closed object of the trigger's fields, none required, because each
/// hook projects the subset it chose.
#[must_use]
pub fn event_data_schema(trigger: HookTrigger) -> Value {
    let uuid =
        |description: &str| json!({"type": "string", "format": "uuid", "description": description});
    let mut properties = Map::new();
    properties.insert(
        "documentId".to_owned(),
        uuid("The document the event is about."),
    );
    properties.insert(
        "versionId".to_owned(),
        uuid("The exact document version the event is about."),
    );
    properties.insert(
        "versionDigest".to_owned(),
        json!({
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
            "description": "The SHA-256 digest of the version's content."
        }),
    );
    properties.insert(
        "policyId".to_owned(),
        json!({
            "type": "string",
            "pattern": "^[a-z][a-z0-9_-]{0,63}$",
            "description": "The document policy the document is held under."
        }),
    );
    properties.insert(
        "policyVersion".to_owned(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": "The version of that policy the document was placed under."
        }),
    );
    if trigger == HookTrigger::DocumentGrantChanged {
        properties.insert(
            "actorKind".to_owned(),
            json!({
                "type": "string",
                "enum": ["service", "human"],
                "description": "The kind of caller that issued or revoked the grant."
            }),
        );
        properties.insert(
            "grantId".to_owned(),
            uuid("The document grant that changed."),
        );
        properties.insert(
            "change".to_owned(),
            json!({
                "type": "string",
                "enum": [GrantChange::Issued.as_str(), GrantChange::Revoked.as_str()],
                "description": "Whether the grant was issued or revoked."
            }),
        );
        properties.insert(
            "expiresAt".to_owned(),
            json!({
                "type": "string",
                "format": "date-time",
                "description": "The expiry frozen into the grant at issue. Reaching it emits no event: the grant stops releasing the version at this instant."
            }),
        );
    }
    debug_assert!(properties.keys().all(|field| {
        DOCUMENT_GRANT_EVENT_FIELDS.contains(&field.as_str())
            && trigger.fields().contains(&field.as_str())
    }));
    let description = match trigger {
        HookTrigger::DocumentVersionReady => {
            "The data of a document-version.ready event: a document version passed content verification and is releasable."
        }
        HookTrigger::DocumentVersionRejected => {
            "The data of a document-version.rejected event: content verification rejected a document version."
        }
        HookTrigger::DocumentGrantChanged => {
            "The data of a document-grant.changed event: a document grant was issued or revoked."
        }
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": trigger.data_schema_id(),
        "title": format!("Registry Stack Document Store {} event data", trigger.as_str()),
        "description": description,
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
    })
}

fn validate_identity(
    identity: &HookRuntimeIdentity,
    schema: &str,
    payload_retention: Duration,
) -> Result<(), HookActivationError> {
    if LocalId::new(identity.project_id.as_str()).is_err()
        || identity.database_id.is_empty()
        || identity.database_id.len() > 256
        || !valid_sha256_digest(&identity.package_digest)
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
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}

#[cfg(test)]
#[path = "hooks_tests.rs"]
mod tests;
