// SPDX-License-Identifier: Apache-2.0

//! The HTTP-facing service: catalogue projections, availability, explain, and
//! the six commitments, each driving the store's one capacity transaction.
//!
//! The service owns three decisions the store cannot. Authorization: a
//! mutating call must carry a task grant whose scheduling permissions cover
//! the offering's service, location, and the operation, and the store
//! re-checks the grant's expiry inside the transaction. Disclosure: every
//! refusal projects to its public problem code here, and only the separately
//! authorized explain path sees the detailed one. Attributability: the
//! commitment's audit entries are built and written here with pseudonymized
//! principal, client, grant, and approver references, the `request` entry
//! before the capacity transaction opens and the `response` entry once it has
//! committed or rolled back, and refused commitments record their receipt so
//! a replayed idempotency key answers as it first did.

use chrono::{DateTime, TimeDelta, Utc};
use registry_platform_audit::{
    AuditKeyHasher, AuditRequest, AuthorizationAuditEvent, AuthorizationOutcome,
};
use registry_platform_calendar::CalendarInterval;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_oidc::{
    task_grant::{TaskGrantError, TaskGrantStatusBinding, TaskGrantStatusRegistry},
    GrantClaims,
};
use registry_scheduling_core::{
    admission_request_hash, evaluate_exact_time_admission, evaluate_exact_time_physical_bundle,
    evaluate_window_admission, location_closure_intervals, location_open_intervals, type_uri,
    AdditionalAllocationRequest, AdmissionRequest, AllocationInterval, AllocationLimits,
    AllocationRequirementDocument, AppointmentDocument, AppointmentHistoryEntryDocument,
    AppointmentStateDocument, AttendanceDocument, AvailabilityEntry, AvailabilityPreviewDocument,
    AvailabilityPreviewRequest, AvailabilitySelection, BundleEvaluationError,
    CancelAppointmentRequest, Channel, CreateAppointmentRequest, ExactTimeBundleContext,
    ExactTimeBundleLineContext, ExactTimeContext, ExactTimeOffering, ExternalReference, LedgerKind,
    LedgerSnapshot, ManagerSelection, OfferingDocument, OfferingPolicy,
    OperationalAllocationDocument, OperationalAppointmentDocument, PageDocument, PartyCounts,
    PoolMember, ProblemCode, PublishedWindow, RecordAttendanceRequest, ReminderDocument,
    RescheduleAppointmentRequest, ResourceDocument, SchedulingFacts, SchedulingMode,
    SchedulingModeDocument, SchedulingPolicy, SchedulingServiceDocument, ServiceDocument,
    StandingAllocation, WindowContext, WindowDocument,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::attendance::AttendanceObservation;
use crate::audit::{request_record, unfinished_record, with_event_id, SchedulingAudit};
use crate::cursors::{
    bind_stored, cursor_expiry, decode_cursor, encode_cursor, CursorError, ListingPosition,
    StoredCursor,
};
use crate::hooks::ActivatedHooks;
use crate::operational::AuthorizedOperationalRead;
use crate::source_busy::{
    busy_reconciliation_request_digest, AuthorizedBusySource, BusyApplyOutcome,
    BusyReconciliationPreview, BusyReconciliationRequest,
};
use crate::store::{
    BundleSupplyLine, BusyStoreError, ClaimRow, ClaimState, CommitError, CommitOutcome,
    CommitSupply, Commitment, PostgresStore, SourceBoundManager, StoreError, SupplyContext,
};

/// The closed action vocabulary a task grant's scheduling permissions carry.
/// A permission names a service, a location, and the actions it allows there;
/// these are the actions the runtime knows.
pub const HOLD_CREATE_ACTION: &str = "hold.create";
pub const HOLD_CREATE_FOR_ACTION: &str = "hold.create-for";
pub const HOLD_RELEASE_ACTION: &str = "hold.release";
pub const APPOINTMENT_CREATE_ACTION: &str = "appointment.create";
pub const APPOINTMENT_CREATE_FOR_ACTION: &str = "appointment.create-for";
pub const APPOINTMENT_READ_ACTION: &str = "appointment.read";
pub const APPOINTMENT_RESCHEDULE_ACTION: &str = "appointment.reschedule";
pub const APPOINTMENT_CANCEL_ACTION: &str = "appointment.cancel";
pub const ATTENDANCE_RECORD_ACTION: &str = "attendance.record";

/// The default and maximum page sizes for every listing.
pub const DEFAULT_PAGE_LIMIT: usize = 50;
pub const MAXIMUM_PAGE_LIMIT: usize = 200;

/// How far one availability search may span. A search is bounded (BKG-01);
/// a wider ask is served from the first 62 days and continues by cursor.
const MAXIMUM_AVAILABILITY_SPAN_DAYS: i64 = 62;

/// The most remaining lifetime the offline path accepts, where no status
/// authority is asked. Only `taskGrantStatus: unchecked-final-fifteen-minutes`
/// selects that path; a deployment that lists status authorities never takes
/// it, for any source, including an unlisted one.
const OFFLINE_TASK_GRANT_REMAINING_SECONDS: u64 = 900;

/// The audit reference class for a booking caller, hashed over the verified
/// issuer and subject pair. History and audit carry this pseudonym, never the
/// raw identity; ownership of a claim is decided on the verified pair instead,
/// so rotating the audit hash key leaves every claim with its owner.
const PRINCIPAL_CLASS: &str = "scheduling-principal-v1";

/// The audit reference class for the authority that minted a credential
/// carrying no task grant. It exists only so a refusal decided before any
/// grant was resolved still names an accountable second party; a different
/// class is a different keyed domain, so a digest written under it can never
/// be mistaken for the pseudonym of a client that actually presented a grant.
const ISSUER_CLASS: &str = "scheduling-issuer-v1";
const SCHEDULING_MANAGER_SUBJECT: &str = "schedulingManager";

/// One verified caller, as the authenticator resolved them.
pub struct Caller {
    /// The verified actor kind: `human`, `agent`, or `service`.
    pub actor_kind: String,
    /// The verified token issuer and subject. A hold or appointment stores
    /// this pair as its owner, and every ownership decision compares it. An
    /// idempotency attempt is identified by a digest over this pair, its
    /// command, and its key, and carries the raw pair only while its receipt
    /// is retained. History and audit carry the pseudonym instead.
    pub issuer: String,
    pub subject: String,
    /// The verified access token's own deadline. Capacity transactions use
    /// the earlier of this and the grant deadline, bounding the interval
    /// between fresh status and commit even for a long-lived grant.
    pub credential_exp_unix: u64,
    /// The verified task grant, when the token carried one.
    pub grant: Option<GrantClaims>,
    /// Subject claims copied only from the verified credential. A task token
    /// may omit them; a configured status registry then refuses the
    /// missing exact binding before a capacity transaction opens.
    pub task_grant_subjects: Option<std::collections::BTreeMap<String, Value>>,
}

impl Caller {
    /// The pseudonymized actor reference history and audit carry.
    pub fn actor_pseudonym(
        &self,
        hasher: &AuditKeyHasher,
        scope: &str,
    ) -> Result<String, ServiceError> {
        let canonical = serde_json::to_string(&(&self.issuer, &self.subject)).map_err(|_| {
            ServiceError::internal("the caller identity could not be canonicalized")
        })?;
        hasher
            .audit_reference_hash(PRINCIPAL_CLASS, scope, &canonical)
            .map_err(|_| ServiceError::internal("the caller identity could not be pseudonymized"))
    }
}

/// What a commitment answered: a minted document, or the stored receipt a
/// replayed idempotency key must receive again.
pub enum CommitmentAnswer<T> {
    Minted(T),
    Replay { status_code: u16, receipt: Value },
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The refusal the caller sees, in its public projection. Every service
    /// failure, internal bound, and cursor verdict lands here too: the edge
    /// renders one problem shape.
    #[error("the request was refused: {}", .0.code())]
    Problem(ProblemCode),
}

impl ServiceError {
    fn internal(reason: &'static str) -> Self {
        tracing::error!(reason, "the Scheduling service hit an internal bound");
        Self::Problem(ProblemCode::ServiceUnavailable)
    }
}

impl From<StoreError> for ServiceError {
    fn from(error: StoreError) -> Self {
        tracing::error!(%error, "the Scheduling store failed");
        Self::Problem(ProblemCode::ServiceUnavailable)
    }
}

impl From<CursorError> for ServiceError {
    fn from(error: CursorError) -> Self {
        match error {
            CursorError::Invalid => Self::Problem(ProblemCode::CursorInvalid),
            CursorError::Expired => Self::Problem(ProblemCode::CursorExpired),
        }
    }
}

impl From<registry_scheduling_core::ResolveError> for ServiceError {
    fn from(error: registry_scheduling_core::ResolveError) -> Self {
        // The policy and the facts do not fit together: an operator state
        // mismatch, never a caller defect, and never disclosed in detail.
        tracing::error!(%error, "the policy and the environment records do not fit together");
        Self::Problem(ProblemCode::ServiceUnavailable)
    }
}

pub struct SchedulingService {
    store: PostgresStore,
    policy: SchedulingPolicy,
    scheduling_id: String,
    policy_revision: u64,
    policy_digest: String,
    hasher: AuditKeyHasher,
    audit: SchedulingAudit,
    attempt_receipt_days: i64,
    hooks: Option<ActivatedHooks>,
    task_grant_status: Option<Arc<TaskGrantStatusRegistry>>,
}

impl SchedulingService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: PostgresStore,
        policy: SchedulingPolicy,
        scheduling_id: String,
        policy_revision: i64,
        policy_digest: String,
        hasher: AuditKeyHasher,
        audit: SchedulingAudit,
        attempt_receipt_days: u32,
    ) -> Self {
        Self {
            store,
            policy,
            scheduling_id,
            policy_revision: u64::try_from(policy_revision).unwrap_or(u64::MAX),
            policy_digest,
            hasher,
            audit,
            attempt_receipt_days: i64::from(attempt_receipt_days),
            hooks: None,
            task_grant_status: None,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: ActivatedHooks) -> Self {
        self.hooks = Some(hooks);
        self
    }

    #[must_use]
    pub fn with_task_grant_status(mut self, status: Option<Arc<TaskGrantStatusRegistry>>) -> Self {
        self.task_grant_status = status;
        self
    }

    fn revision(&self) -> u64 {
        self.policy_revision
    }

    /// The instant requests are decided under: the store's clock, which is
    /// the system clock in production. Handlers read time here so that none
    /// reaches around the service to the store.
    pub(crate) fn observed_now(&self) -> DateTime<Utc> {
        self.store.observed_now()
    }

    /// Whether the database is at this release's schema and the audit
    /// destination still accepts entries.
    pub async fn ready(&self) -> Result<(), ServiceError> {
        self.store
            .ready()
            .await
            .map_err(|_| ServiceError::Problem(ProblemCode::ServiceUnavailable))?;
        self.audit_ready().await
    }

    /// Whether the audit destination every commitment writes to still accepts
    /// entries. A stopped writer refuses every commitment, so this answers
    /// unavailable rather than let readiness report a process that cannot
    /// commit.
    pub async fn audit_ready(&self) -> Result<(), ServiceError> {
        if self.audit.ready().await {
            Ok(())
        } else {
            Err(ServiceError::Problem(ProblemCode::ServiceUnavailable))
        }
    }

    /// Which deployment and which policy this service answers with.
    pub fn scheduling(&self) -> SchedulingServiceDocument {
        SchedulingServiceDocument {
            scheduling_id: self.scheduling_id.clone(),
            policy_revision: self.policy_revision,
            policy_digest: self.policy_digest.clone(),
        }
    }

    pub async fn list_services(
        &self,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<ServiceDocument>, ServiceError> {
        let limit = page_limit(limit);
        let position = self.resolve_position(cursor, "services", now).await?;
        let mut services: Vec<_> = self
            .policy
            .services
            .iter()
            .map(|service| ServiceDocument {
                id: service.id.clone(),
                label: service.label.clone(),
            })
            .collect();
        services.sort_by(|a, b| a.id.cmp(&b.id));
        page_of(self, services, position, limit, "services", now).await
    }

    pub async fn list_offerings(
        &self,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<OfferingDocument>, ServiceError> {
        let limit = page_limit(limit);
        let position = self.resolve_position(cursor, "offerings", now).await?;
        let (facts, _) = self.store.facts().await?;
        let mut offerings: Vec<_> = self
            .policy
            .offerings
            .iter()
            .map(|offering| self.offering_document(offering, &facts))
            .collect::<Result<_, _>>()?;
        offerings.sort_by(|a, b| a.id.cmp(&b.id));
        page_of(self, offerings, position, limit, "offerings", now).await
    }

    pub async fn list_resources(
        &self,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<ResourceDocument>, ServiceError> {
        let limit = page_limit(limit);
        let position = self.resolve_position(cursor, "resources", now).await?;
        let after = id_position(position)?;
        let rows = self
            .store
            .list_resources(after.as_deref(), limit as i64 + 1)
            .await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(
                |(resource_id, pool, capabilities, available, capacity_units)| ResourceDocument {
                    resource_id,
                    pool,
                    capabilities,
                    available,
                    capacity_units,
                },
            )
            .collect();
        let next_cursor = if more {
            Some(
                self.mint_cursor("resources", &position_of_last_id(&items), now)
                    .await?,
            )
        } else {
            None
        };
        Ok(PageDocument { items, next_cursor })
    }

    pub async fn list_locations(
        &self,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<registry_scheduling_core::LocationDocument>, ServiceError> {
        let limit = page_limit(limit);
        let position = self.resolve_position(cursor, "locations", now).await?;
        let after = id_position(position)?;
        let rows = self
            .store
            .list_locations(after.as_deref(), limit as i64 + 1)
            .await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(
                |(location_id, timezone)| registry_scheduling_core::LocationDocument {
                    location_id,
                    timezone,
                },
            )
            .collect();
        let next_cursor = if more {
            Some(
                self.mint_cursor("locations", &position_of_last_id(&items), now)
                    .await?,
            )
        } else {
            None
        };
        Ok(PageDocument { items, next_cursor })
    }

    /// Preview one source-owned busy reconciliation through the same
    /// fail-closed audit destination as other attributable operations.
    pub async fn preview_source_busy(
        &self,
        authority: &AuthorizedBusySource,
        request: &BusyReconciliationRequest,
    ) -> Result<BusyReconciliationPreview, BusyStoreError> {
        let request_digest = busy_reconciliation_request_digest(request, authority)
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        let record = self.busy_source_audit_record(
            authority,
            request,
            &request_digest,
            "source-busy.preview",
        )?;
        let mut audit = self
            .audit
            .begin(
                Uuid::new_v4(),
                record.clone(),
                busy_source_audit_response(record.clone(), "unfinished", "audit.unfinished"),
            )
            .await
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        let result = self
            .store
            .preview_busy_reconciliation(authority, request)
            .await;
        let response = match &result {
            Ok(preview) => busy_source_audit_result(
                record,
                "previewed",
                preview.current_revision,
                preview.added,
                preview.changed,
                preview.deleted,
                &preview.impacts,
            ),
            Err(error) => {
                busy_source_audit_response(record, "refused", busy_source_audit_reason(error))
            }
        };
        audit
            .respond(response)
            .await
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        result
    }

    /// Apply one source-owned snapshot only after its request audit is
    /// accepted, then gate the response on the matching outcome entry.
    pub async fn apply_source_busy(
        &self,
        authority: &AuthorizedBusySource,
        request: &BusyReconciliationRequest,
    ) -> Result<BusyApplyOutcome, BusyStoreError> {
        let request_digest = busy_reconciliation_request_digest(request, authority)
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        let record = self.busy_source_audit_record(
            authority,
            request,
            &request_digest,
            "source-busy.apply",
        )?;
        let mut audit = self
            .audit
            .begin(
                Uuid::new_v4(),
                record.clone(),
                busy_source_audit_response(record.clone(), "unfinished", "audit.unfinished"),
            )
            .await
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        let result = self
            .store
            .apply_busy_reconciliation(authority, request)
            .await;
        let response = match &result {
            Ok(applied) => busy_source_audit_result(
                record,
                match applied.kind {
                    crate::source_busy::BusyApplyOutcomeKind::Applied => "applied",
                    crate::source_busy::BusyApplyOutcomeKind::AlreadyApplied => "already-applied",
                },
                applied.revision,
                applied.added,
                applied.changed,
                applied.deleted,
                &applied.impacts,
            ),
            Err(error) => {
                busy_source_audit_response(record, "refused", busy_source_audit_reason(error))
            }
        };
        audit
            .respond(response)
            .await
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        result
    }

    fn busy_source_audit_record(
        &self,
        authority: &AuthorizedBusySource,
        request: &BusyReconciliationRequest,
        request_digest: &str,
        operation: &str,
    ) -> Result<Value, BusyStoreError> {
        let actor = authority
            .actor_pseudonym(&self.hasher, &self.scheduling_id)
            .map_err(|_| BusyStoreError::AuditUnavailable)?;
        Ok(json!({
            "event": operation,
            "actor": actor,
            "profile": authority.profile_id(),
            "requestDigest": request_digest,
            "expectedRevision": request.expected_revision,
            "status": match request.status {
                crate::source_busy::BusySourceStatus::Fresh => "fresh",
                crate::source_busy::BusySourceStatus::Unavailable => "unavailable",
            },
            "coverageStart": request.coverage.start,
            "coverageEnd": request.coverage.end,
            "resourceCount": request.coverage.resources.len(),
            "recordCount": request.records.len(),
        }))
    }

    /// Bounded availability. Exact-time offerings answer in grid slots,
    /// arrival-window offerings in windows. Only entries with capacity left
    /// are listed: a slot nobody can serve or a window with no units left is
    /// not availability.
    pub async fn availability(
        &self,
        offering_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<AvailabilityEntry>, ServiceError> {
        self.availability_with_selection(
            offering_id,
            start,
            end,
            cursor,
            limit,
            &AvailabilitySelection::default(),
            now,
        )
        .await
    }

    /// Availability for the exact duration and resource the caller intends
    /// to request. A cursor belongs to those choices as well as its bounds.
    #[allow(clippy::too_many_arguments)]
    pub async fn availability_with_selection(
        &self,
        offering_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: Option<usize>,
        selection: &AvailabilitySelection,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<AvailabilityEntry>, ServiceError> {
        let limit = page_limit(limit);
        let offering = self.published_offering(offering_id)?;
        if offering.exact_time.is_none()
            && (selection.duration_minutes.is_some() || selection.resource.is_some())
        {
            return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
        }
        let span = TimeDelta::days(MAXIMUM_AVAILABILITY_SPAN_DAYS);
        // A continuation restores the effective interval of the request that
        // minted its cursor. A default availability request, with neither
        // start nor end, has no bounds of its own to repeat, so it reads
        // them from the cursor rather than deriving a different interval
        // from this request's own now; bounds a caller does supply must
        // repeat the minted interval exactly, and anything else is a
        // different listing the cursor refuses.
        let stored = match cursor {
            Some(encoded) => Some(self.stored_cursor(encoded).await?),
            None => None,
        };
        let minted_interval = match &stored {
            Some(row) => match ListingPosition::from_json(&row.position) {
                Some(ListingPosition::AvailabilityAfter { from, to, .. }) => Some((from, to)),
                _ => return Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
            },
            None => None,
        };
        let from = start
            .or(minted_interval.map(|(from, _)| from))
            .unwrap_or(now);
        let to = match end {
            Some(end) => end
                .max(saturating_later(from, TimeDelta::minutes(1)))
                .min(saturating_later(from, span)),
            None => minted_interval
                .map(|(_, to)| to)
                .unwrap_or(saturating_later(from, span)),
        };
        let mut context = format!("availability:{offering_id}:{}:{to}", from.to_rfc3339());
        if selection.duration_minutes.is_some() || selection.resource.is_some() {
            let choices = serde_json::to_string(selection)
                .map_err(|_| ServiceError::internal("availability choices could not be encoded"))?;
            context.push_str(":selection:");
            context.push_str(&choices);
        }
        let position = match stored {
            Some(ref row) => Some(bind_stored(row, &context, now)?),
            None => None,
        };
        let after = match position {
            Some(ListingPosition::AvailabilityAfter { after, .. }) => Some(after),
            Some(_) => return Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
            None => None,
        };
        let entries = match self.supply(offering).await?.0 {
            ResolvedSupply::ExactTime {
                mut exact,
                mut members,
                open,
                ..
            } => {
                exact.duration_minutes = exact
                    .selected_duration_minutes(selection.duration_minutes)
                    .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
                if let Some(resource) = &selection.resource {
                    if !exact.allow_resource_selection {
                        return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
                    }
                    members.retain(|member| member.resource_id == *resource);
                    if members.is_empty() {
                        return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
                    }
                }
                let duration = TimeDelta::minutes(i64::from(exact.duration_minutes));
                let buffer = TimeDelta::minutes(
                    i64::from(exact.buffer_before_minutes) + i64::from(exact.buffer_after_minutes),
                );
                let ids: Vec<String> = members.iter().map(|m| m.resource_id.clone()).collect();
                // The snapshot window widens by the duration and both buffers:
                // a booking that intrudes on any listed slot's occupied span
                // must be in the snapshot, wherever it starts.
                let snapshot = self
                    .store
                    .member_snapshot(
                        &ids,
                        saturating_earlier(from, buffer),
                        saturating_later(to, duration + buffer),
                        now,
                    )
                    .await?;
                exact_time_slots(
                    &exact,
                    &members,
                    &offering.requires_capabilities,
                    &open,
                    &snapshot,
                    from,
                    to,
                    now,
                )
            }
            ResolvedSupply::Window {
                windows,
                lead_time_minutes,
                horizon_days,
                open,
                ..
            } => {
                // Each served window is its own capacity, read from its own
                // anchor; a window outside the range is never read.
                let mut entries = Vec::new();
                for window in windows
                    .iter()
                    .filter(|window| window.start >= from && window.start < to)
                {
                    let snapshot = self.store.window_snapshot(&window.id, now).await?;
                    entries.extend(window_entries(
                        window,
                        &snapshot,
                        from,
                        to,
                        now,
                        lead_time_minutes,
                        horizon_days,
                        &open,
                    ));
                }
                entries
            }
        };
        let selected: Vec<_> = entries
            .into_iter()
            .filter(|entry| match &after {
                Some(after) => entry_instant(entry) > *after,
                None => true,
            })
            .collect();
        let more = selected.len() > limit;
        let items: Vec<_> = selected.into_iter().take(limit).collect();
        let next_cursor = if more {
            let last = entry_instant(items.last().expect("a limited page is not empty"));
            let position = ListingPosition::AvailabilityAfter {
                from,
                to,
                after: last,
            };
            Some(self.mint_cursor(&context, &position, now).await?)
        } else {
            None
        };
        Ok(PageDocument { items, next_cursor })
    }

    /// The separately authorized explanation of one start: the public and the
    /// detailed code of the refusal a booking would receive, or no codes at
    /// all when the start admits as things stand. The probe is a minimal
    /// party that already meets the offering's declared input requirements,
    /// so the codes explain the calendar and capacity rather than repeating
    /// requirements the operator already knows this synthetic probe must
    /// carry. It never names another caller's booking.
    pub async fn explain(
        &self,
        offering_id: &str,
        start: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<registry_scheduling_core::ExplainDocument, ServiceError> {
        self.explain_with_selection(offering_id, start, &AvailabilitySelection::default(), now)
            .await
    }

    /// Explain the same explicit duration and resource choices used by
    /// availability and admission, without reserving capacity.
    pub async fn explain_with_selection(
        &self,
        offering_id: &str,
        start: DateTime<Utc>,
        selection: &AvailabilitySelection,
        now: DateTime<Utc>,
    ) -> Result<registry_scheduling_core::ExplainDocument, ServiceError> {
        let offering = self.published_offering(offering_id)?;
        let probe = AdmissionRequest {
            offering: offering.id.clone(),
            start,
            duration_minutes: selection.duration_minutes,
            resource: selection.resource.clone(),
            resource_units: 1,
            additional_allocations: Vec::new(),
            party: Some(registry_scheduling_core::PartyCounts {
                recipients: 1,
                attendees: 1,
            }),
            manager: None,
            channel: None,
            duplicate_key: None,
            policy_revision: self.revision(),
            window_revision: None,
            capabilities: offering.requires_capabilities.clone(),
            prerequisites: offering.prerequisites.clone(),
            external_references: Vec::new(),
            party_references: Vec::new(),
        };
        let refusal = match self.supply(offering).await?.0 {
            ResolvedSupply::ExactTime {
                exact,
                members,
                open,
                closures,
            } => {
                let duration = TimeDelta::minutes(i64::from(
                    exact
                        .selected_duration_minutes(selection.duration_minutes)
                        .unwrap_or(exact.duration_minutes),
                ));
                let buffer = TimeDelta::minutes(
                    i64::from(exact.buffer_before_minutes) + i64::from(exact.buffer_after_minutes),
                );
                let ids: Vec<String> = members.iter().map(|m| m.resource_id.clone()).collect();
                let snapshot = self
                    .store
                    .member_snapshot(
                        &ids,
                        saturating_earlier(start, buffer + duration),
                        saturating_later(start, duration + buffer),
                        now,
                    )
                    .await?;
                evaluate_exact_time_admission(
                    &ExactTimeContext {
                        offering,
                        exact: &exact,
                        members: &members,
                        open: &open,
                        closures: &closures,
                        snapshot: &snapshot,
                        policy_revision: self.revision(),
                        now,
                    },
                    &probe,
                    // A probe replaces nothing; it explains the start as an
                    // ordinary booking would meet it.
                    None,
                )
                .err()
            }
            ResolvedSupply::Window {
                windows,
                lead_time_minutes,
                horizon_days,
                channels,
                open,
                closures,
            } => match offering.arrival_window(&windows, start) {
                Some(window) => {
                    // The probe carries the window's current revision, the
                    // way a booking request would: window admission checks
                    // capacity only under a revision the caller actually
                    // observed, and an explain that never names one answers
                    // every window with a revision mismatch instead of
                    // explaining the start.
                    let mut probe = probe.clone();
                    probe.window_revision = Some(window.revision);
                    let snapshot = self.store.window_snapshot(&window.id, now).await?;
                    evaluate_window_admission(
                        &WindowContext {
                            offering,
                            window,
                            open: &open,
                            closures: &closures,
                            lead_time_minutes,
                            horizon_days,
                            snapshot: &snapshot,
                            policy_revision: self.revision(),
                            channels: &channels,
                            now,
                        },
                        &probe,
                        // A probe replaces nothing here either.
                        None,
                    )
                    .err()
                }
                // No served window opens at the start: the refusal a booking
                // there receives.
                None => Some(registry_scheduling_core::AdmissionRefusal::ScheduleUnpublished),
            },
        };
        Ok(registry_scheduling_core::ExplainDocument {
            offering: offering.id.clone(),
            start,
            public_code: refusal
                .as_ref()
                .map(|refusal| refusal.public_code().code().to_owned()),
            detailed_code: refusal
                .as_ref()
                .map(|refusal| refusal.detailed_code().code().to_owned()),
            explanation: refusal.as_ref().map(ToString::to_string),
        })
    }

    /// Read-scoped physical capacity advice for a complete exact-time bundle.
    /// This path checks the bundle's physical requirements directly, without
    /// asking for or inferring caller eligibility.
    pub async fn preview_availability(
        &self,
        preview: &AvailabilityPreviewRequest,
        now: DateTime<Utc>,
    ) -> Result<AvailabilityPreviewDocument, ServiceError> {
        let (bundle, _facts_revision) = self.preview_supply(preview).await?;
        let lines = bundle.contexts()?;
        let primary = lines
            .first()
            .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
        let duration_minutes = primary
            .exact
            .selected_duration_minutes(preview.duration_minutes)
            .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
        let end = preview
            .start
            .checked_add_signed(TimeDelta::minutes(i64::from(duration_minutes)))
            .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
        let maximum_before = lines
            .iter()
            .map(|line| line.exact.buffer_before_minutes)
            .max()
            .unwrap_or(0);
        let maximum_after = lines
            .iter()
            .map(|line| line.exact.buffer_after_minutes)
            .max()
            .unwrap_or(0);
        let from = preview
            .start
            .checked_sub_signed(TimeDelta::minutes(i64::from(maximum_before)))
            .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
        let to = end
            .checked_add_signed(TimeDelta::minutes(i64::from(maximum_after)))
            .ok_or(ServiceError::Problem(ProblemCode::RequestUnprocessable))?;
        let mut resources: Vec<_> = lines
            .iter()
            .flat_map(|line| line.members.iter().map(|member| member.resource_id.clone()))
            .collect();
        resources.sort();
        resources.dedup();
        let snapshot = self
            .store
            .bundle_preview_snapshot(&resources, from, to, now)
            .await?;

        let contexts: Vec<_> = lines
            .iter()
            .map(|line| ExactTimeBundleLineContext {
                requirement_id: line.requirement_id.clone(),
                offering: line.offering,
                exact: line.exact,
                members: line.members,
                open: line.open,
                closures: line.closures,
                resource: line.resource,
                stored_resource: false,
                units: line.units,
            })
            .collect();
        let within_horizon = lines.iter().all(|line| {
            start_is_within_horizon(
                preview.start,
                now,
                line.exact.lead_time_minutes,
                line.exact.horizon_days,
            )
        });
        let party_fits = preview.party.is_none_or(|party| {
            lines
                .iter()
                .all(|line| party_fits_exact_time(party, line.exact))
        });
        let capacity_available = if within_horizon && party_fits {
            match evaluate_exact_time_physical_bundle(
                &ExactTimeBundleContext {
                    lines: &contexts,
                    snapshot: &snapshot,
                    policy_revision: self.revision(),
                    now,
                    exclude_reservation: None,
                    confirming_hold: false,
                    limits: AllocationLimits {
                        maximum_requirements:
                            registry_scheduling_core::MAXIMUM_ALLOCATION_REQUIREMENTS,
                        maximum_units_per_requirement:
                            registry_scheduling_core::MAXIMUM_RESOURCE_UNITS,
                        maximum_candidate_resources: 256,
                        maximum_standing_allocations: 4_096,
                    },
                },
                preview.start,
                duration_minutes,
            ) {
                Ok(_) => true,
                Err(BundleEvaluationError::Allocation(
                    registry_scheduling_core::AllocationError::CapacityExhausted { .. },
                )) => false,
                Err(BundleEvaluationError::Admission(refusal))
                    if refusal.public_code() != ProblemCode::RequestUnprocessable =>
                {
                    false
                }
                Err(_) => return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable)),
            }
        } else {
            false
        };
        Ok(AvailabilityPreviewDocument {
            offering: preview.offering.clone(),
            start: preview.start,
            end,
            capacity_available,
            public_code: (!capacity_available).then(|| "capacity.exhausted".to_owned()),
        })
    }

    /// Reserve an admission instead of committing it.
    pub async fn create_hold(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        request: &AdmissionRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<registry_scheduling_core::HoldDocument>, ServiceError> {
        let offering = self.published_offering(&request.offering)?;
        let assisted = request.manager == Some(ManagerSelection::SchedulingManager);
        let operation = if assisted {
            HOLD_CREATE_FOR_ACTION
        } else {
            HOLD_CREATE_ACTION
        };
        let grant = self.require_permission(caller, offering, operation).await?;
        let source_manager = if assisted {
            Some(
                self.require_source_manager(caller, &grant, None, operation)
                    .await?,
            )
        } else {
            None
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self
            .request_supply(caller, operation, assisted, request, false)
            .await?;
        let request_hash = admission_request_hash(request);
        let mut commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            facts_revision,
        )?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(caller, &grant, operation, now, assisted)
            .await?;
        let outcome = match &supply {
            ResolvedRequestSupply::Exact(bundle) => {
                let contexts = bundle.contexts()?;
                self.store
                    .create_hold(
                        &CommitSupply::Bundle(&contexts),
                        request,
                        self.policy.hold_policy.ttl_minutes,
                        self.policy.hold_policy.maximum_per_caller,
                        commitment,
                    )
                    .await
            }
            ResolvedRequestSupply::Window(supply) => {
                match supply.context_at(offering, request.start) {
                    Some(context) => {
                        self.store
                            .create_hold(
                                &CommitSupply::Single {
                                    offering,
                                    supply: &context,
                                },
                                request,
                                self.policy.hold_policy.ttl_minutes,
                                self.policy.hold_policy.maximum_per_caller,
                                commitment,
                            )
                            .await
                    }
                    None => Err(no_window_at_start()),
                }
            }
        };
        let answer = self
            .commitment_outcome(
                outcome,
                correlation,
                caller,
                &grant,
                &actor,
                idempotency_key,
                &request_hash,
                "hold:create",
                operation,
                now,
                facts_revision,
            )
            .await?;
        Ok(claim_or_replay(answer, |claim, receipt| {
            hold_document(claim, &self.policy, self.revision(), receipt)
        }))
    }

    /// Give a hold's capacity back. The release carries no caller-chosen
    /// idempotency key on the wire, so the key is the hold's own id: a
    /// retried release of the same hold replays the first answer.
    pub async fn release_hold(
        &self,
        caller: &Caller,
        hold_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<()>, ServiceError> {
        let hold = self
            .hold(hold_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let offering = self.claim_offering(&hold, now).await?;
        let grant = self
            .require_permission(caller, &offering, HOLD_RELEASE_ACTION)
            .await?;
        let source_manager = match hold.source_manager.as_ref() {
            Some(expected) => Some(
                self.require_source_manager(caller, &grant, Some(expected), HOLD_RELEASE_ACTION)
                    .await?,
            ),
            None => None,
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let request_hash = canonical_hash(&json!({"hold": hold_id}))?;
        // The release carries no caller-chosen key, so the hold's own id is
        // the idempotency key: a retried release replays the first answer.
        let release_key = hold_id.to_string();
        // A release evaluates no supply, so no records revision guards it:
        // closing a hold cannot name a resource.
        let mut commitment =
            self.commitment(caller, &actor, &grant, &release_key, &request_hash, now, 0)?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(
                caller,
                &grant,
                HOLD_RELEASE_ACTION,
                now,
                hold.source_manager.is_some(),
            )
            .await?;
        let outcome = self.store.release_hold(hold_id, commitment).await;
        self.commitment_outcome(
            outcome,
            correlation,
            caller,
            &grant,
            &actor,
            &release_key,
            &request_hash,
            &format!("hold:{hold_id}:release"),
            HOLD_RELEASE_ACTION,
            now,
            0,
        )
        .await
    }

    /// Confirm a held allocation, or create an appointment directly.
    pub async fn create_appointment(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        request: &CreateAppointmentRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<AppointmentDocument>, ServiceError> {
        match (&request.hold, &request.admission) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(ServiceError::Problem(ProblemCode::RequestInvalid));
            }
            _ => {}
        }
        let answer = match &request.hold {
            Some(hold) => {
                let hold_id = Uuid::parse_str(hold)
                    .map_err(|_| ServiceError::Problem(ProblemCode::RequestInvalid))?;
                self.confirm_appointment(caller, idempotency_key, hold_id, now)
                    .await
            }
            None => {
                let admission = request.admission.as_ref().expect("checked above");
                self.direct_create_appointment(caller, idempotency_key, admission, now)
                    .await
            }
        }?;
        Ok(claim_or_replay(answer, |claim, receipt| {
            appointment_document(claim, &self.policy, self.revision(), receipt)
        }))
    }

    async fn confirm_appointment(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        hold_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<ClaimRow>, ServiceError> {
        let hold = self
            .hold(hold_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let offering = self.policy.offering(&hold.offering).ok_or_else(|| {
            ServiceError::internal("a committed hold names no offering in the policy")
        })?;
        let assisted = hold.source_manager.is_some();
        let operation = if assisted {
            APPOINTMENT_CREATE_FOR_ACTION
        } else {
            APPOINTMENT_CREATE_ACTION
        };
        let grant = self.require_permission(caller, offering, operation).await?;
        let source_manager = match hold.source_manager.as_ref() {
            Some(expected) => Some(
                self.require_source_manager(caller, &grant, Some(expected), operation)
                    .await?,
            ),
            None => None,
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let confirmation_request = self.confirmation_request(&hold)?;
        // Every exact-time hold this runtime writes carries allocation rows,
        // and a publication refuses to change the mode of an offering with
        // an active hold. An active exact-time hold without any rows is
        // therefore an inconsistent ledger: the window path below writes a
        // booking with no allocation, and consuming the hold would release
        // its capacity to a second booking. A closed or expired hold
        // consumes nothing, so it keeps the store's replay and refusal
        // answers.
        if confirmation_request.is_none()
            && offering.mode == SchedulingMode::ExactTime
            && hold.state == ClaimState::Active
            && hold.hold_expires_at.is_some_and(|expiry| expiry > now)
        {
            return Err(ServiceError::internal(
                "an active exact-time hold has no allocation rows; the claim ledger is inconsistent",
            ));
        }
        let (supply, facts_revision) = if let Some(request) = confirmation_request.as_ref() {
            self.request_supply(caller, operation, assisted, request, true)
                .await?
        } else {
            let (supply, revision) = self.supply(offering).await?;
            (ResolvedRequestSupply::Window(supply), revision)
        };
        let request_hash = canonical_hash(&json!({"hold": hold_id}))?;
        let mut commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            facts_revision,
        )?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(caller, &grant, operation, now, assisted)
            .await?;
        let outcome = match (&supply, confirmation_request.as_ref()) {
            (ResolvedRequestSupply::Exact(bundle), Some(request)) => {
                let contexts = bundle.contexts()?;
                self.store
                    .confirm_hold(
                        hold_id,
                        &CommitSupply::Bundle(&contexts),
                        Some(request),
                        commitment,
                    )
                    .await
            }
            (ResolvedRequestSupply::Window(supply), _) => {
                match supply.context_for_hold(offering, &hold) {
                    Some(context) => {
                        self.store
                            .confirm_hold(
                                hold_id,
                                &CommitSupply::Single {
                                    offering,
                                    supply: &context,
                                },
                                None,
                                commitment,
                            )
                            .await
                    }
                    None => Err(no_window_at_start()),
                }
            }
            _ => Err(StoreError::Corrupt.into()),
        };
        self.commitment_outcome(
            outcome,
            correlation,
            caller,
            &grant,
            &actor,
            idempotency_key,
            &request_hash,
            &format!("hold:{hold_id}:confirm"),
            operation,
            now,
            facts_revision,
        )
        .await
    }

    fn confirmation_request(
        &self,
        hold: &ClaimRow,
    ) -> Result<Option<AdmissionRequest>, ServiceError> {
        if hold.allocations.is_empty() {
            return Ok(None);
        }
        let mut grouped = BTreeMap::<u16, Vec<_>>::new();
        for allocation in &hold.allocations {
            let key = match allocation.requirement {
                AllocationRequirementDocument::Primary => 0,
                AllocationRequirementDocument::Additional { index } => u16::from(index) + 1,
            };
            grouped.entry(key).or_default().push(allocation);
        }
        let primary_parts = grouped
            .remove(&0)
            .ok_or_else(|| ServiceError::internal("an exact hold has no primary allocation"))?;
        let duration_minutes = hold
            .displayed_end
            .signed_duration_since(hold.displayed_start)
            .num_minutes();
        let duration_minutes = u32::try_from(duration_minutes).map_err(|_| {
            ServiceError::internal("a committed hold has an invalid displayed interval")
        })?;
        let grouped_request = |parts: Vec<&registry_scheduling_core::AllocationDocument>| {
            let first = parts[0];
            if parts.iter().any(|part| part.offering != first.offering) {
                return Err(ServiceError::internal(
                    "one committed requirement names multiple offerings",
                ));
            }
            let units = parts.iter().try_fold(0_u32, |total, part| {
                total.checked_add(part.units).ok_or_else(|| {
                    ServiceError::internal("a committed requirement quantity overflows")
                })
            })?;
            Ok((
                first.offering.clone(),
                (parts.len() == 1).then(|| first.resource.clone()),
                units,
            ))
        };
        let (primary_offering, primary_resource, primary_units) = grouped_request(primary_parts)?;
        let mut additional_allocations = Vec::with_capacity(grouped.len());
        for (expected, (key, parts)) in grouped.into_iter().enumerate() {
            if usize::from(key) != expected + 1 {
                return Err(ServiceError::internal(
                    "an exact hold has non-contiguous additional allocation identities",
                ));
            }
            let (offering, resource, units) = grouped_request(parts)?;
            additional_allocations.push(AdditionalAllocationRequest {
                offering,
                resource,
                units,
            });
        }
        let mut capabilities = Vec::new();
        let mut prerequisites = Vec::new();
        for allocation in &hold.allocations {
            let offering = self.policy.offering(&allocation.offering).ok_or_else(|| {
                ServiceError::internal("a committed hold allocation names no current offering")
            })?;
            capabilities.extend(offering.requires_capabilities.iter().cloned());
            prerequisites.extend(offering.prerequisites.iter().cloned());
        }
        capabilities.sort();
        capabilities.dedup();
        prerequisites.sort();
        prerequisites.dedup();
        Ok(Some(AdmissionRequest {
            offering: primary_offering,
            start: hold.displayed_start,
            duration_minutes: Some(duration_minutes),
            resource: primary_resource,
            resource_units: primary_units,
            additional_allocations,
            party: hold.party,
            manager: None,
            channel: hold.channel.clone(),
            duplicate_key: hold.duplicate_key.clone(),
            policy_revision: self.revision(),
            window_revision: None,
            capabilities,
            prerequisites,
            external_references: hold.external_references.clone(),
            party_references: hold.party_references.clone(),
        }))
    }

    async fn direct_create_appointment(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        request: &AdmissionRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<ClaimRow>, ServiceError> {
        let offering = self.published_offering(&request.offering)?;
        let assisted = request.manager == Some(ManagerSelection::SchedulingManager);
        let operation = if assisted {
            APPOINTMENT_CREATE_FOR_ACTION
        } else {
            APPOINTMENT_CREATE_ACTION
        };
        let grant = self.require_permission(caller, offering, operation).await?;
        let source_manager = if assisted {
            Some(
                self.require_source_manager(caller, &grant, None, operation)
                    .await?,
            )
        } else {
            None
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self
            .request_supply(caller, operation, assisted, request, false)
            .await?;
        let request_hash = admission_request_hash(request);
        let mut commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            facts_revision,
        )?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(caller, &grant, operation, now, assisted)
            .await?;
        let outcome = match &supply {
            ResolvedRequestSupply::Exact(bundle) => {
                let contexts = bundle.contexts()?;
                self.store
                    .create_appointment(&CommitSupply::Bundle(&contexts), request, commitment)
                    .await
            }
            ResolvedRequestSupply::Window(supply) => {
                match supply.context_at(offering, request.start) {
                    Some(context) => {
                        self.store
                            .create_appointment(
                                &CommitSupply::Single {
                                    offering,
                                    supply: &context,
                                },
                                request,
                                commitment,
                            )
                            .await
                    }
                    None => Err(no_window_at_start()),
                }
            }
        };
        self.commitment_outcome(
            outcome,
            correlation,
            caller,
            &grant,
            &actor,
            idempotency_key,
            &request_hash,
            "appointment:create",
            operation,
            now,
            facts_revision,
        )
        .await
    }

    /// Observe the original success receipt without replaying a command.
    /// Ordinary read authority is checked at the HTTP boundary; lookup stays
    /// scoped to the verified issuer and subject even after task authority ends.
    pub async fn appointment_receipt(
        &self,
        caller: &Caller,
        key: &str,
        request: &CreateAppointmentRequest,
        now: DateTime<Utc>,
    ) -> Result<AppointmentDocument, ServiceError> {
        let (scope, request_hash) = match (&request.hold, &request.admission) {
            (None, Some(admission)) => (
                "appointment:create".to_owned(),
                admission_request_hash(admission),
            ),
            (Some(hold), None) => {
                let hold = Uuid::parse_str(hold)
                    .map_err(|_| ServiceError::Problem(ProblemCode::RequestInvalid))?;
                (
                    format!("hold:{hold}:confirm"),
                    canonical_hash(&json!({"hold": hold}))?,
                )
            }
            _ => return Err(ServiceError::Problem(ProblemCode::RequestInvalid)),
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let record = json!({"event": "scheduling.appointment.receipt-read", "actor": actor});
        let mut audit = self.audit.begin(Uuid::new_v4(), record.clone(),
            json!({"event": "scheduling.appointment.receipt-read", "actor": actor, "outcome": "unfinished"}))
            .await.map_err(|_| ServiceError::Problem(ProblemCode::ServiceUnavailable))?;
        let result = async {
            let receipt = self
                .store
                .appointment_receipt(
                    &caller.issuer,
                    &caller.subject,
                    &scope,
                    key,
                    &request_hash,
                    now,
                )
                .await?
                .ok_or(ServiceError::Problem(ProblemCode::ReceiptUnresolved))?;
            let claim = receipt
                .get("claim")
                .cloned()
                .and_then(|value| serde_json::from_value::<ClaimRow>(value).ok())
                .ok_or(ServiceError::Problem(ProblemCode::ReceiptUnresolved))?;
            if receipt.get("kind").and_then(Value::as_str) != Some("booking") {
                return Err(ServiceError::Problem(ProblemCode::ReceiptUnresolved));
            }
            Ok(appointment_document(
                &claim,
                &self.policy,
                self.revision(),
                Some(&receipt),
            ))
        }
        .await;
        let mut response = record;
        response["outcome"] = json!(if result.is_ok() {
            "observed"
        } else {
            "unresolved"
        });
        audit
            .respond(response)
            .await
            .map_err(|_| ServiceError::Problem(ProblemCode::ServiceUnavailable))?;
        result
    }

    /// One appointment by id under retained ownership or a current detail grant.
    /// Detail grants name the service and location; source-managed claims also
    /// require their retained manager binding. They do not bind an appointment id.
    pub async fn get_appointment(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<AppointmentDocument, ServiceError> {
        let claim = self
            .booking(appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        match claim.source_manager.as_ref() {
            None if claim.is_owned_by(&caller.issuer, &caller.subject) => {}
            None if claim.owner.is_some() => {
                let offering = self.claim_offering(&claim, now).await?;
                let grant = self
                    .require_permission(caller, &offering, APPOINTMENT_READ_ACTION)
                    .await?;
                self.require_current_task_grant(caller, &grant, APPOINTMENT_READ_ACTION, now, true)
                    .await?;
            }
            None => return Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized)),
            Some(expected) => {
                let offering = self.claim_offering(&claim, now).await?;
                let grant = self
                    .require_permission(caller, &offering, APPOINTMENT_READ_ACTION)
                    .await?;
                self.require_source_manager(
                    caller,
                    &grant,
                    Some(expected),
                    APPOINTMENT_READ_ACTION,
                )
                .await?;
                self.require_current_task_grant(caller, &grant, APPOINTMENT_READ_ACTION, now, true)
                    .await?;
            }
        }
        let mut document = appointment_document(&claim, &self.policy, self.revision(), None);
        document.attendance = self
            .store
            .current_attendance(appointment_id)
            .await?
            .as_ref()
            .map(|observation| observation.document())
            .transpose()
            .map_err(|_| ServiceError::internal("stored attendance is invalid"))?;
        Ok(document)
    }

    /// List this caller's appointments carrying one opaque external record
    /// reference. Ownership is applied on every page; the cursor also binds
    /// a digest of the same verified caller and the exact reference so it
    /// cannot be moved across either boundary.
    pub async fn list_appointments(
        &self,
        caller: &Caller,
        reference: &ExternalReference,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<AppointmentDocument>, ServiceError> {
        let owner_hash = canonical_hash(&json!([&caller.issuer, &caller.subject]))?;
        let reference_hash = canonical_hash(&serde_json::to_value(reference).map_err(|_| {
            ServiceError::internal("the external reference could not be canonicalized")
        })?)?;
        let context = format!("appointments:{owner_hash}:{reference_hash}");
        let position = self.resolve_position(cursor, &context, now).await?;
        let after_id = id_position(position)?
            .map(|value| Uuid::parse_str(&value))
            .transpose()
            .map_err(|_| ServiceError::Problem(ProblemCode::CursorInvalid))?;
        let limit = page_limit(limit);
        let mut claims = self
            .store
            .list_appointments_by_external_reference(
                &caller.issuer,
                &caller.subject,
                reference,
                after_id,
                i64::try_from(limit + 1).unwrap_or(i64::MAX),
            )
            .await?;
        let more = claims.len() > limit;
        claims.truncate(limit);
        let next_cursor = if more {
            let last_id = claims
                .last()
                .expect("a page with more rows has one row")
                .claim_id
                .to_string();
            Some(
                self.mint_cursor(&context, &ListingPosition::AfterId { last_id }, now)
                    .await?,
            )
        } else {
            None
        };
        Ok(PageDocument {
            items: claims
                .iter()
                .map(|claim| appointment_document(claim, &self.policy, self.revision(), None))
                .collect(),
            next_cursor,
        })
    }

    /// List appointments under one freshly authorized operational profile.
    /// The cursor context includes the handle digest, so every continuation is
    /// rebound to the same caller, profile revision and normalized filters.
    pub async fn list_operational_appointments(
        &self,
        authority: &AuthorizedOperationalRead,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<OperationalAppointmentDocument>, ServiceError> {
        let context = format!("operational-appointments:{}", authority.context_digest());
        let position = self.resolve_position(cursor, &context, now).await?;
        let after = match position {
            Some(ListingPosition::OperationalAfter { after, last_id }) => Some((
                after,
                Uuid::parse_str(&last_id)
                    .map_err(|_| ServiceError::Problem(ProblemCode::CursorInvalid))?,
            )),
            Some(_) => return Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
            None => None,
        };
        let limit = page_limit(limit);
        let mut rows = self
            .store
            .list_operational_appointments(
                authority,
                after,
                i64::try_from(limit + 1).unwrap_or(i64::MAX),
            )
            .await?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if more {
            let last = rows.last().expect("a page with more rows has one row");
            Some(
                self.mint_cursor(
                    &context,
                    &ListingPosition::OperationalAfter {
                        after: last.position_start,
                        last_id: last.appointment_id.to_string(),
                    },
                    now,
                )
                .await?,
            )
        } else {
            None
        };
        let items = rows
            .into_iter()
            .map(|row| {
                Ok(OperationalAppointmentDocument {
                    appointment_id: row.appointment_id.to_string(),
                    revision: u64::try_from(row.revision).map_err(|_| {
                        ServiceError::internal("an operational appointment revision is invalid")
                    })?,
                    service: row.service,
                    location: row.location,
                    offering: row.offering,
                    state: row.state,
                    displayed_start: row.displayed_start,
                    displayed_end: row.displayed_end,
                    occupied_start: row.occupied_start,
                    occupied_end: row.occupied_end,
                    resource: row.resource,
                    units: row
                        .units
                        .map(u32::try_from)
                        .transpose()
                        .map_err(|_| ServiceError::internal("operational units are invalid"))?,
                    party: row.party,
                    allocations: row
                        .allocations
                        .map(|allocations| {
                            allocations
                                .into_iter()
                                .map(|allocation| {
                                    Ok(OperationalAllocationDocument {
                                        requirement: allocation.requirement,
                                        offering: allocation.offering,
                                        resource: allocation.resource,
                                        units: u32::try_from(allocation.units).map_err(|_| {
                                            ServiceError::internal(
                                                "operational allocation units are invalid",
                                            )
                                        })?,
                                        occupied_start: allocation.occupied_start,
                                        occupied_end: allocation.occupied_end,
                                    })
                                })
                                .collect::<Result<Vec<_>, ServiceError>>()
                        })
                        .transpose()?,
                    attendance: row
                        .attendance
                        .as_ref()
                        .map(|observation| observation.document())
                        .transpose()
                        .map_err(|_| ServiceError::internal("stored attendance is invalid"))?,
                    external_references: row.external_references,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        Ok(PageDocument { items, next_cursor })
    }

    pub async fn reschedule_appointment(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
        idempotency_key: &str,
        request: &RescheduleAppointmentRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<AppointmentDocument>, ServiceError> {
        // The pre-read resolves the offering for the permission check; kind,
        // state, revision, and ownership are re-checked inside the
        // transaction, where a refusal is an auditable decision.
        let appointment = self
            .booking(appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let offering = self.policy.offering(&appointment.offering).ok_or_else(|| {
            ServiceError::internal("a committed appointment names no offering in the policy")
        })?;
        let grant = self
            .require_permission(caller, offering, APPOINTMENT_RESCHEDULE_ACTION)
            .await?;
        let source_manager = match appointment.source_manager.as_ref() {
            Some(expected) => Some(
                self.require_source_manager(
                    caller,
                    &grant,
                    Some(expected),
                    APPOINTMENT_RESCHEDULE_ACTION,
                )
                .await?,
            ),
            None => None,
        };
        if request.admission.offering != appointment.offering {
            return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
        }
        if !request.admission.external_references.is_empty()
            || !request.admission.party_references.is_empty()
            || request.admission.manager.is_some()
        {
            return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
        }
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self
            .request_supply(
                caller,
                APPOINTMENT_RESCHEDULE_ACTION,
                appointment.source_manager.is_some(),
                &request.admission,
                false,
            )
            .await?;
        let request_hash = canonical_hash(&json!({
            "observedRevision": request.observed_revision,
            "admissionHash": admission_request_hash(&request.admission),
        }))?;
        let mut commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            facts_revision,
        )?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(
                caller,
                &grant,
                APPOINTMENT_RESCHEDULE_ACTION,
                now,
                appointment.source_manager.is_some(),
            )
            .await?;
        let outcome = match &supply {
            ResolvedRequestSupply::Exact(bundle) => {
                let contexts = bundle.contexts()?;
                self.store
                    .reschedule_appointment(
                        appointment_id,
                        &CommitSupply::Bundle(&contexts),
                        &request.admission,
                        request.observed_revision,
                        commitment,
                    )
                    .await
            }
            ResolvedRequestSupply::Window(supply) => {
                match supply.context_at(offering, request.admission.start) {
                    Some(context) => {
                        self.store
                            .reschedule_appointment(
                                appointment_id,
                                &CommitSupply::Single {
                                    offering,
                                    supply: &context,
                                },
                                &request.admission,
                                request.observed_revision,
                                commitment,
                            )
                            .await
                    }
                    None => Err(no_window_at_start()),
                }
            }
        };
        let answer = self
            .commitment_outcome(
                outcome,
                correlation,
                caller,
                &grant,
                &actor,
                idempotency_key,
                &request_hash,
                &format!("appointment:{appointment_id}:reschedule"),
                APPOINTMENT_RESCHEDULE_ACTION,
                now,
                facts_revision,
            )
            .await?;
        Ok(claim_or_replay(answer, |claim, receipt| {
            appointment_document(claim, &self.policy, self.revision(), receipt)
        }))
    }

    /// Append or correct the explicit attendance observation for the current
    /// logical visit. This never changes the booking or its capacity claim.
    pub async fn record_attendance(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
        idempotency_key: &str,
        request: &RecordAttendanceRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<AttendanceDocument>, ServiceError> {
        if request.observed_at > now {
            return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
        }
        let appointment = self
            .booking(appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let offering = self.claim_offering(&appointment, now).await?;
        let grant = self
            .require_permission(caller, &offering, ATTENDANCE_RECORD_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let grant_reference = format!(
            "sha256:{}",
            hex(&Sha256::digest(
                [
                    b"scheduling-attendance-grant-v1\0".as_slice(),
                    self.scheduling_id.as_bytes(),
                    b"\0",
                    grant.id().as_bytes(),
                ]
                .concat()
            ))
        );
        let request_hash = canonical_hash(
            &serde_json::to_value(request)
                .map_err(|_| ServiceError::internal("attendance could not be canonicalized"))?,
        )?;
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            0,
        )?;
        let (correlation, _request) = self
            .audit_request(caller, &grant, ATTENDANCE_RECORD_ACTION, now, false)
            .await?;
        let outcome = self
            .store
            .record_attendance(appointment_id, request, &grant_reference, commitment)
            .await;
        let answer: CommitmentAnswer<AttendanceObservation> = self
            .commitment_outcome(
                outcome,
                correlation,
                caller,
                &grant,
                &actor,
                idempotency_key,
                &request_hash,
                &format!("appointment:{appointment_id}:attendance"),
                ATTENDANCE_RECORD_ACTION,
                now,
                0,
            )
            .await?;
        match answer {
            CommitmentAnswer::Minted(observation) => {
                Ok(CommitmentAnswer::Minted(observation.document().map_err(
                    |_| ServiceError::internal("stored attendance is invalid"),
                )?))
            }
            CommitmentAnswer::Replay { receipt, .. } => {
                let document = serde_json::from_value::<AttendanceDocument>(receipt)
                    .map_err(|_| ServiceError::internal("stored attendance receipt is invalid"))?;
                Ok(CommitmentAnswer::Minted(document))
            }
        }
    }

    pub async fn cancel_appointment(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
        idempotency_key: &str,
        request: &CancelAppointmentRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<AppointmentDocument>, ServiceError> {
        let appointment = self
            .booking(appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let offering = self.claim_offering(&appointment, now).await?;
        let grant = self
            .require_permission(caller, &offering, APPOINTMENT_CANCEL_ACTION)
            .await?;
        let source_manager = match appointment.source_manager.as_ref() {
            Some(expected) => Some(
                self.require_source_manager(
                    caller,
                    &grant,
                    Some(expected),
                    APPOINTMENT_CANCEL_ACTION,
                )
                .await?,
            ),
            None => None,
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let request_hash = canonical_hash(&json!({
            "observedRevision": request.observed_revision,
            "reason": request.reason,
        }))?;
        // A cancellation evaluates no supply, so no records revision guards
        // it: closing an appointment cannot name a resource.
        let mut commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            now,
            0,
        )?;
        commitment.source_manager = source_manager;
        let (correlation, _request) = self
            .audit_request(
                caller,
                &grant,
                APPOINTMENT_CANCEL_ACTION,
                now,
                appointment.source_manager.is_some(),
            )
            .await?;
        let outcome = self
            .store
            .cancel_appointment(
                appointment_id,
                request.observed_revision,
                Some(offering.cancellation_cutoff_minutes),
                offering.exact_time.is_some(),
                request.reason.as_deref(),
                commitment,
            )
            .await;
        let answer = self
            .commitment_outcome(
                outcome,
                correlation,
                caller,
                &grant,
                &actor,
                idempotency_key,
                &request_hash,
                &format!("appointment:{appointment_id}:cancel"),
                APPOINTMENT_CANCEL_ACTION,
                now,
                0,
            )
            .await?;
        Ok(claim_or_replay(answer, |claim, receipt| {
            appointment_document(claim, &self.policy, self.revision(), receipt)
        }))
    }

    /// The attributable history of one appointment, newest first, visible to
    /// the caller that owns it.
    pub async fn appointment_history(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
        cursor: Option<&str>,
        limit: Option<usize>,
        now: DateTime<Utc>,
    ) -> Result<PageDocument<AppointmentHistoryEntryDocument>, ServiceError> {
        let limit = page_limit(limit);
        self.owned_booking(caller, appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        let context = format!("history:{appointment_id}");
        let position = self.resolve_position(cursor, &context, now).await?;
        let before = match position {
            Some(ListingPosition::BeforeInstantAndId { before, last_id }) => Some((
                before,
                Uuid::parse_str(&last_id)
                    .map_err(|_| ServiceError::internal("a stored history position is corrupt"))?,
            )),
            Some(_) => return Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
            None => None,
        };
        let rows = self
            .store
            .claim_history(appointment_id, before, limit as i64 + 1)
            .await?;
        let more = rows.len() > limit;
        let page: Vec<_> = rows.into_iter().take(limit).collect();
        let items = page
            .iter()
            .map(history_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if more {
            let last = items.last().expect("a limited page is not empty");
            let position = ListingPosition::BeforeInstantAndId {
                before: last.occurred_at,
                last_id: last.event_id.clone(),
            };
            Some(self.mint_cursor(&context, &position, now).await?)
        } else {
            None
        };
        Ok(PageDocument { items, next_cursor })
    }

    /// The booking a claim names, when it is one. `None` covers a claim the
    /// caller may not act on as a booking: unknown, not a booking, or
    /// another caller's. Mutating paths take the ownership refusal from the
    /// store, where it is auditable; read paths take it here, where hiding
    /// existence is the contract.
    async fn booking(&self, appointment_id: Uuid) -> Result<Option<ClaimRow>, ServiceError> {
        let Some(claim) = self.store.claim(appointment_id).await? else {
            return Ok(None);
        };
        if claim.kind != LedgerKind::Booking {
            return Ok(None);
        }
        Ok(Some(claim))
    }

    /// The hold a claim names, when it is one. `None` covers a claim that
    /// cannot answer a hold action pre-check: unknown, or not a hold.
    /// Release and confirmation take this before checking permission, so an
    /// id that names nothing and an id that names a hold the caller's grant
    /// does not reach must answer alike; whether the hold is still active is
    /// a decision the store makes instead, where it is auditable.
    async fn hold(&self, hold_id: Uuid) -> Result<Option<ClaimRow>, ServiceError> {
        let Some(claim) = self.store.claim(hold_id).await? else {
            return Ok(None);
        };
        if claim.kind != LedgerKind::Hold {
            return Ok(None);
        }
        Ok(Some(claim))
    }

    /// `booking`, and the caller owns it.
    async fn owned_booking(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
    ) -> Result<Option<ClaimRow>, ServiceError> {
        let Some(claim) = self.booking(appointment_id).await? else {
            return Ok(None);
        };
        if claim.source_manager.is_some() || !claim.is_owned_by(&caller.issuer, &caller.subject) {
            return Ok(None);
        }
        Ok(Some(claim))
    }

    fn offering_document(
        &self,
        offering: &OfferingPolicy,
        facts: &SchedulingFacts,
    ) -> Result<OfferingDocument, ServiceError> {
        let mode = match offering.mode {
            SchedulingMode::ExactTime => SchedulingModeDocument::ExactTime,
            SchedulingMode::ArrivalWindow => SchedulingModeDocument::ArrivalWindow,
        };
        let (duration, buffer_before, buffer_after, increment, max_recipients) =
            match &offering.exact_time {
                Some(exact) => (
                    Some(exact.duration_minutes),
                    Some(exact.buffer_before_minutes),
                    Some(exact.buffer_after_minutes),
                    Some(exact.start_increment_minutes),
                    Some(exact.maximum_recipients),
                ),
                None => (None, None, None, None, None),
            };
        let window_document = |window: &PublishedWindow| WindowDocument {
            id: window.id.clone(),
            revision: window.revision,
            start: window.start,
            end: window.end,
            units: window.units,
        };
        // An offering that names its window publishes it as `window`, as it
        // always has; one that names none publishes every window it serves
        // as `windows`.
        let (window, windows) = match &offering.arrival {
            Some(arrival) if arrival.window.is_some() => (
                served_windows(facts, offering)?
                    .first()
                    .map(window_document),
                Vec::new(),
            ),
            Some(_) => (
                None,
                served_windows(facts, offering)?
                    .iter()
                    .map(window_document)
                    .collect(),
            ),
            None => (None, Vec::new()),
        };
        let (lead_time_minutes, horizon_days) = match (&offering.exact_time, &offering.arrival) {
            (Some(exact), None) => (exact.lead_time_minutes, exact.horizon_days),
            (None, Some(arrival)) => (arrival.lead_time_minutes, arrival.horizon_days),
            _ => (0, 0),
        };
        Ok(OfferingDocument {
            id: offering.id.clone(),
            service: offering.service.clone(),
            label: offering.label.clone(),
            mode,
            location: offering.location.clone(),
            lead_time_minutes,
            horizon_days,
            cancellation_cutoff_minutes: offering.cancellation_cutoff_minutes,
            duration_minutes: duration,
            duration_selection: offering.exact_time.as_ref().and_then(|exact| {
                exact.duration_selection.as_ref().map(|selection| {
                    registry_scheduling_core::DurationSelectionDocument {
                        minimum_minutes: selection.minimum_minutes,
                        maximum_minutes: selection.maximum_minutes,
                        increment_minutes: selection.increment_minutes,
                    }
                })
            }),
            opening_coverage: offering
                .exact_time
                .as_ref()
                .map(|exact| exact.opening_coverage)
                .unwrap_or_default(),
            allow_resource_selection: offering
                .exact_time
                .as_ref()
                .is_some_and(|exact| exact.allow_resource_selection),
            pool: offering
                .exact_time
                .as_ref()
                .and_then(|exact| exact.allow_resource_selection.then(|| exact.pool.clone())),
            buffer_before_minutes: buffer_before,
            buffer_after_minutes: buffer_after,
            start_increment_minutes: increment,
            party_counts: offering
                .exact_time
                .as_ref()
                .map_or(Default::default(), |exact| exact.party_counts),
            max_recipients,
            window,
            windows,
            reminders: offering
                .reminders
                .iter()
                .map(|reminder| ReminderDocument {
                    minutes_before: reminder.offset_minutes,
                })
                .collect(),
            requires_capabilities: offering.requires_capabilities.clone(),
            prerequisites: offering.prerequisites.clone(),
        })
    }

    /// The offering the deployed policy publishes under `offering_id`.
    ///
    /// An offering the policy does not publish is not a precondition the
    /// caller can satisfy by reloading and retrying, which is what
    /// `precondition.failed` invites: it does not exist, and the offering
    /// listing is where a caller learns what does. That listing is readable by
    /// every caller holding the reads scope, so naming the absence discloses
    /// nothing the listing would not.
    fn published_offering(&self, offering_id: &str) -> Result<&OfferingPolicy, ServiceError> {
        self.policy
            .offering(offering_id)
            .ok_or(ServiceError::Problem(ProblemCode::RequestNotFound))
    }

    /// A grant that covers this offering's service, location, and action, or
    /// the refusal. Readable availability is not authority to book: the
    /// permission must name all three.
    ///
    /// Both refusals are audited, and answered only once their entry is
    /// accepted. A refusal decided here never opens the
    /// capacity transaction, so nothing further in the request would record
    /// that it happened, and a caller probing which services and locations its
    /// grant reaches would leave no audit entry. Each refusal is one `response`
    /// entry with a correlation of its own. What the audit gains is the
    /// attribution: the answer stays the same closed code, naming neither
    /// the bound that failed nor whether a grant was carried at all.
    async fn require_permission(
        &self,
        caller: &Caller,
        offering: &OfferingPolicy,
        action: &str,
    ) -> Result<GrantClaims, ServiceError> {
        let Some(grant) = &caller.grant else {
            self.record_refusal(
                Uuid::new_v4(),
                grantless_refusal_record(&self.hasher, &self.scheduling_id, caller, action),
            )
            .await?;
            return Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized));
        };
        let allowed = grant
            .bounds()
            .scheduling_permissions()
            .is_some_and(|permissions| {
                permissions.iter().any(|permission| {
                    permission.service() == offering.service.as_str()
                        && permission.location() == offering.location.as_str()
                        && permission
                            .actions()
                            .iter()
                            .any(|allowed| allowed.as_str() == action)
                })
            });
        if allowed {
            Ok(grant.clone())
        } else {
            self.record_refusal(
                Uuid::new_v4(),
                audit_record(
                    &self.hasher,
                    &self.scheduling_id,
                    caller,
                    grant,
                    action,
                    AuthorizationOutcome::Denied,
                    "authorization.refused",
                ),
            )
            .await?;
            Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized))
        }
    }

    /// Resolve the only source-bound manager Scheduling understands. The
    /// request selects the fixed subject name, while the signed grant supplies
    /// its value and source. A caller-provided record reference is never used.
    async fn require_source_manager(
        &self,
        caller: &Caller,
        grant: &GrantClaims,
        expected: Option<&SourceBoundManager>,
        operation: &str,
    ) -> Result<SourceBoundManager, ServiceError> {
        let manager = caller
            .task_grant_subjects
            .as_ref()
            .and_then(|subjects| subjects.get(SCHEDULING_MANAGER_SUBJECT))
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
            })
            .map(|subject| SourceBoundManager {
                source_issuer: grant.source_issuer().to_owned(),
                subject: subject.to_owned(),
            });
        if let Some(manager) = manager.filter(|manager| expected.is_none_or(|it| it == manager)) {
            return Ok(manager);
        }
        self.record_refusal(
            Uuid::new_v4(),
            audit_record(
                &self.hasher,
                &self.scheduling_id,
                caller,
                grant,
                operation,
                AuthorizationOutcome::Denied,
                "authorization.refused",
            ),
        )
        .await?;
        Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized))
    }

    /// Write one refusal, or one commitment nothing decided, as the
    /// `response` entry of `correlation`, whose identity it also carries as
    /// `eventId`. It fails closed like an allowed response: a refusal whose
    /// entry the destination does not accept is answered
    /// `service.unavailable`, so no refusal is answered without its audit.
    async fn record_refusal(
        &self,
        correlation: Uuid,
        record: Result<Value, ServiceError>,
    ) -> Result<(), ServiceError> {
        let record = with_event_id(correlation, record?).ok_or_else(|| {
            ServiceError::internal("the refusal audit record carries another identity")
        })?;
        self.audit
            .response(correlation, record)
            .await
            .map_err(|failure| {
                tracing::error!(%failure, "the refusal audit entry was refused");
                ServiceError::Problem(ProblemCode::ServiceUnavailable)
            })
    }

    /// Establish that this exact grant is current immediately before the
    /// request audit and capacity transaction. No database lock is held while
    /// the remote authority is called. A configured registry is authoritative
    /// for every source, so an unknown source is a refusal and never reaches
    /// the bounded offline path.
    async fn require_current_task_grant(
        &self,
        caller: &Caller,
        grant: &GrantClaims,
        operation: &str,
        now: DateTime<Utc>,
        online_required: bool,
    ) -> Result<(), ServiceError> {
        let now = u64::try_from(now.timestamp()).map_err(|_| {
            ServiceError::internal("the task-grant clock observation is not representable")
        })?;
        let verdict = if online_required && self.task_grant_status.is_none() {
            Err(TaskGrantError::Refused)
        } else {
            task_grant_verdict(
                self.task_grant_status.as_deref(),
                caller.task_grant_subjects.clone(),
                grant,
                now,
            )
            .await
        };
        match verdict {
            Ok(()) => Ok(()),
            Err(TaskGrantError::Refused) => {
                self.record_refusal(
                    Uuid::new_v4(),
                    audit_record(
                        &self.hasher,
                        &self.scheduling_id,
                        caller,
                        grant,
                        operation,
                        AuthorizationOutcome::Denied,
                        "authorization.refused",
                    ),
                )
                .await?;
                Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized))
            }
            Err(TaskGrantError::Unavailable) => {
                tracing::warn!("the task-grant authority could not establish current status");
                Err(ServiceError::Problem(ProblemCode::ServiceUnavailable))
            }
            Err(TaskGrantError::Configuration) => {
                tracing::error!("the activated task-grant status registry became unusable");
                Err(ServiceError::Problem(ProblemCode::ServiceUnavailable))
            }
        }
    }

    /// Append the `request` entry of one commitment and return the
    /// correlation its `response` entry will carry, with the handle that owes
    /// it. It names the caller, the grant, and the operation the capacity
    /// transaction will decide, and no outcome. A destination that refuses it
    /// refuses the commitment: the capacity transaction does not open. The
    /// caller holds the handle until it answers: the response written under
    /// the correlation answers it, and a commitment that returns or is
    /// canceled before then writes the `commitment.unfinished` response.
    async fn audit_request(
        &self,
        caller: &Caller,
        grant: &GrantClaims,
        operation: &str,
        now: DateTime<Utc>,
        online_required: bool,
    ) -> Result<(Uuid, AuditRequest), ServiceError> {
        self.require_current_task_grant(caller, grant, operation, now, online_required)
            .await?;
        let record = audit_record(
            &self.hasher,
            &self.scheduling_id,
            caller,
            grant,
            operation,
            AuthorizationOutcome::Allowed,
            "authorization.allowed",
        )?;
        let correlation = Uuid::new_v4();
        let unfinished = with_event_id(
            correlation,
            unfinished_record(record.clone(), "commitment.unfinished"),
        )
        .ok_or_else(|| ServiceError::internal("the commitment audit record carries an identity"))?;
        let request = self
            .audit
            .begin(correlation, request_record(record), unfinished)
            .await
            .map_err(|failure| {
                tracing::error!(%failure, "the commitment request audit entry was refused");
                ServiceError::Problem(ProblemCode::ServiceUnavailable)
            })?;
        Ok((correlation, request))
    }

    /// Append the `response` entry that gates an answer: the allowed entry
    /// of a committed commitment, or the entry of a replayed receipt. A
    /// refusal here answers the caller `service.unavailable` and releases
    /// nothing. A committed commitment stays in place, and a retry under the
    /// same idempotency key replays its receipt, gated the same way.
    async fn audit_response(
        &self,
        correlation: Uuid,
        caller: &Caller,
        grant: &GrantClaims,
        operation: &str,
        (outcome, reason): (AuthorizationOutcome, &str),
    ) -> Result<(), ServiceError> {
        let record = audit_record(
            &self.hasher,
            &self.scheduling_id,
            caller,
            grant,
            operation,
            outcome,
            reason,
        )?;
        let record = with_event_id(correlation, record).ok_or_else(|| {
            ServiceError::internal("the commitment audit record carries another identity")
        })?;
        self.audit
            .response(correlation, record)
            .await
            .map_err(|failure| {
                tracing::error!(
                    %failure,
                    "the commitment's response audit entry was refused"
                );
                ServiceError::Problem(ProblemCode::ServiceUnavailable)
            })
    }

    /// Release a stored receipt only once its `response` entry is accepted.
    /// The entry records the decision the receipt carries, so a replayed
    /// refusal is recorded as the refusal it replays, not as allowed.
    async fn audited_replay<T>(
        &self,
        correlation: Uuid,
        caller: &Caller,
        grant: &GrantClaims,
        operation: &str,
        status_code: u16,
        receipt: Value,
    ) -> Result<CommitmentAnswer<T>, ServiceError> {
        self.audit_response(
            correlation,
            caller,
            grant,
            operation,
            replayed_decision(status_code, &receipt),
        )
        .await?;
        Ok(CommitmentAnswer::Replay {
            status_code,
            receipt,
        })
    }

    /// The offering a committed claim names.
    ///
    /// The current policy answers for a claim that still pins it, because
    /// publication refuses to change the service, location, mode or supply of
    /// an offering while such a claim stands: the live terms and the ones the
    /// claim was committed under are the same terms. Every other claim, a
    /// closed one or a hold already past its expiry, pins nothing. Its
    /// offering may since have been retired, or kept its identifier and been
    /// sold under a different service, and the retry its receipt exists to
    /// serve still has to be authorized before that receipt is replayed. So
    /// the terms are read from the policy revision the claim itself names,
    /// and the grant is matched against the offering as it stood when the
    /// claim was committed: the caller who committed it can still close it,
    /// and a grant over whatever the identifier sells today cannot reach a
    /// receipt written under something else.
    async fn claim_offering(
        &self,
        claim: &ClaimRow,
        now: DateTime<Utc>,
    ) -> Result<Cow<'_, OfferingPolicy>, ServiceError> {
        if claim.pins_its_offering(now) {
            if let Some(current) = self.policy.offering(&claim.offering) {
                return Ok(Cow::Borrowed(current));
            }
        }
        self.store
            .retained_offering(claim.policy_revision, &claim.offering)
            .await?
            .map(Cow::Owned)
            .ok_or_else(|| {
                ServiceError::internal(
                    "a committed claim names no offering in the policy revision it was committed under",
                )
            })
    }

    /// The policy-resolved supply an offering runs against, read from the
    /// live facts the operator's records apply wrote, with the records
    /// revision the read observed. The revision travels into the capacity
    /// transaction, which refuses to commit against records a replacement
    /// has since superseded.
    async fn supply(
        &self,
        offering: &OfferingPolicy,
    ) -> Result<(ResolvedSupply, i64), ServiceError> {
        let (facts, revision) = self.store.facts().await?;
        Ok((
            ResolvedSupply::resolve(&self.policy, &facts, offering)?,
            revision,
        ))
    }

    async fn request_supply<'a>(
        &'a self,
        caller: &Caller,
        operation: &str,
        assisted: bool,
        request: &AdmissionRequest,
        stored_resources: bool,
    ) -> Result<(ResolvedRequestSupply<'a>, i64), ServiceError> {
        let (facts, revision) = self.store.facts().await?;
        let primary = self.published_offering(&request.offering)?;
        let primary_supply = ResolvedSupply::resolve(&self.policy, &facts, primary)?;
        if matches!(primary_supply, ResolvedSupply::Window { .. }) {
            if request.resource_units != 1 || !request.additional_allocations.is_empty() {
                return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
            }
            return Ok((ResolvedRequestSupply::Window(primary_supply), revision));
        }

        validate_bundle_width(request.additional_allocations.len())?;
        let mut lines =
            Vec::with_capacity(registry_scheduling_core::MAXIMUM_ALLOCATION_REQUIREMENTS);
        lines.push(ResolvedExactBundleLine {
            requirement_id: "primary".to_owned(),
            offering: primary,
            supply: primary_supply,
            resource: request.resource.clone(),
            stored_resource: stored_resources,
            units: request.resource_units,
        });
        for (index, additional) in request.additional_allocations.iter().enumerate() {
            let offering = self.published_offering(&additional.offering)?;
            let grant = self.require_permission(caller, offering, operation).await?;
            if assisted {
                self.require_source_manager(caller, &grant, None, operation)
                    .await?;
            }
            let supply = ResolvedSupply::resolve(&self.policy, &facts, offering)?;
            if !matches!(supply, ResolvedSupply::ExactTime { .. }) {
                return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
            }
            lines.push(ResolvedExactBundleLine {
                requirement_id: format!("additional:{index}"),
                offering,
                supply,
                resource: additional.resource.clone(),
                stored_resource: stored_resources,
                units: additional.units,
            });
        }
        Ok((
            ResolvedRequestSupply::Exact(ResolvedExactBundle { lines }),
            revision,
        ))
    }

    async fn preview_supply<'a>(
        &'a self,
        request: &AvailabilityPreviewRequest,
    ) -> Result<(ResolvedExactBundle<'a>, i64), ServiceError> {
        let (facts, revision) = self.store.facts().await?;
        let primary = self.published_offering(&request.offering)?;
        let primary_supply = ResolvedSupply::resolve(&self.policy, &facts, primary)?;
        if !matches!(primary_supply, ResolvedSupply::ExactTime { .. }) {
            return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
        }
        validate_bundle_width(request.additional_allocations.len())?;
        let mut lines =
            Vec::with_capacity(registry_scheduling_core::MAXIMUM_ALLOCATION_REQUIREMENTS);
        lines.push(ResolvedExactBundleLine {
            requirement_id: "primary".to_owned(),
            offering: primary,
            supply: primary_supply,
            resource: request.resource.clone(),
            stored_resource: false,
            units: request.resource_units,
        });
        for (index, additional) in request.additional_allocations.iter().enumerate() {
            let offering = self.published_offering(&additional.offering)?;
            let supply = ResolvedSupply::resolve(&self.policy, &facts, offering)?;
            if !matches!(supply, ResolvedSupply::ExactTime { .. }) {
                return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
            }
            lines.push(ResolvedExactBundleLine {
                requirement_id: format!("additional:{index}"),
                offering,
                supply,
                resource: additional.resource.clone(),
                stored_resource: false,
                units: additional.units,
            });
        }
        Ok((ResolvedExactBundle { lines }, revision))
    }

    #[allow(clippy::too_many_arguments)]
    fn commitment<'a>(
        &'a self,
        caller: &'a Caller,
        actor: &'a str,
        grant: &GrantClaims,
        idempotency_key: &'a str,
        request_hash: &'a str,
        now: DateTime<Utc>,
        facts_revision: i64,
    ) -> Result<Commitment<'a>, ServiceError> {
        let attempt_expires_at = now
            .checked_add_signed(TimeDelta::days(self.attempt_receipt_days))
            .ok_or_else(|| {
                ServiceError::internal("the attempt retention horizon is not representable")
            })?;
        Ok(Commitment {
            now,
            policy_revision: i64::try_from(self.policy_revision).unwrap_or(i64::MAX),
            facts_revision,
            actor,
            actor_issuer: &caller.issuer,
            actor_subject: &caller.subject,
            source_manager: None,
            idempotency_key,
            request_hash,
            attempt_expires_at,
            grant_exp_unix: Some(grant.exp().min(caller.credential_exp_unix)),
            hooks: self.hooks.as_ref(),
        })
    }

    /// Translate one store outcome: minted, replayed, or refused. A minted
    /// commitment is answered only once its allowed `response` entry is
    /// accepted, and a replayed receipt, including one a concurrent identical
    /// request won, only once the `response` entry recording its decision
    /// is. A refusal writes its receipt under the caller's idempotency key so
    /// a replay of that key answers the same, and is answered only once its
    /// `response` entry is accepted: denied for a decision the ledger took,
    /// `unfinished` with its reason for a failed transaction, a replaced
    /// environment, a refused idempotency key, or a commit whose outcome
    /// could not be read back. A commit that took effect though its
    /// acknowledgment was lost reaches here as minted. Every entry carries the
    /// `correlation` of the commitment's `request` entry.
    #[allow(clippy::too_many_arguments)]
    async fn commitment_outcome<T>(
        &self,
        outcome: Result<CommitOutcome, CommitError>,
        correlation: Uuid,
        caller: &Caller,
        grant: &GrantClaims,
        actor: &str,
        idempotency_key: &str,
        request_hash: &str,
        scope: &str,
        operation: &str,
        now: DateTime<Utc>,
        facts_revision: i64,
    ) -> Result<CommitmentAnswer<T>, ServiceError>
    where
        T: FromMinted,
    {
        match outcome {
            Ok(CommitOutcome::Replay {
                status_code,
                receipt,
            }) => {
                self.audited_replay(correlation, caller, grant, operation, status_code, receipt)
                    .await
            }
            Ok(minted) => {
                self.audit_response(
                    correlation,
                    caller,
                    grant,
                    operation,
                    (AuthorizationOutcome::Allowed, "authorization.allowed"),
                )
                .await?;
                Ok(CommitmentAnswer::Minted(T::from_minted(minted)))
            }
            Err(error) => {
                let mut problem = problem_of(&error);
                // Every commitment answers its request entry, refused as much
                // as allowed, and one nothing decided as well. The match is
                // exhaustive on purpose: a new variant must state which side
                // it falls on rather than inherit silence from a wildcard.
                let mut response = match &error {
                    // The transaction failed and the caller sees no detail.
                    CommitError::Store(_) | CommitError::Query(_) | CommitError::Hooks(_) => {
                        tracing::error!(%error, "the Scheduling store failed mid-commitment");
                        Unanswered::Unfinished("commitment.failed")
                    }
                    // The commit was not acknowledged and its read-back
                    // failed, so it may have taken effect: this records the
                    // outcome as unknown, never as failed.
                    CommitError::Unacknowledged => {
                        tracing::error!(%error, "a Scheduling commitment's outcome is unknown");
                        Unanswered::Unfinished("commitment.unfinished")
                    }
                    // A records replacement moved under this request, and the
                    // caller retries; the swap is an expected operator act, so
                    // this is a warning, not a failure.
                    CommitError::FactsStale => {
                        tracing::warn!(
                            %error,
                            "the environment records were replaced while a commitment was in flight"
                        );
                        Unanswered::Unfinished("commitment.facts-stale")
                    }
                    // The idempotency layer refused the key, not the
                    // commitment, and the key says nothing about what a grant
                    // reaches, so this is no authorization decision.
                    CommitError::KeyReused | CommitError::KeyExpired => {
                        Unanswered::Unfinished(key_refusal_reason(&error))
                    }
                    CommitError::Unauthorized => Unanswered::Denied("authorization.refused"),
                    CommitError::Refused(_)
                    | CommitError::HoldCeiling
                    | CommitError::RevisionMismatch
                    | CommitError::ObservationInFuture
                    | CommitError::CutoffPassed => Unanswered::Denied("authorization.profile"),
                };
                // A refusal writes its receipt so a replay of the key answers
                // the same. A failed transaction and a replaced environment
                // decided nothing, an unacknowledged commit may already hold
                // the key's receipt, and an expired receipt cannot be
                // recreated. A reused key still passes through the
                // insert-or-replay path: a concurrent identical winner is
                // replayed, while a different request hash remains key-reused.
                let receipted = !matches!(
                    error,
                    CommitError::Store(_)
                        | CommitError::Query(_)
                        | CommitError::Hooks(_)
                        | CommitError::FactsStale
                        | CommitError::KeyExpired
                        | CommitError::Unacknowledged
                );
                if receipted {
                    let receipt = self.commitment(
                        caller,
                        actor,
                        grant,
                        idempotency_key,
                        request_hash,
                        now,
                        facts_revision,
                    );
                    match receipt {
                        Ok(commitment) => {
                            match self
                                .store
                                .record_refused_attempt(
                                    &commitment,
                                    scope,
                                    problem.http_status(),
                                    problem_receipt(problem),
                                )
                                .await
                            {
                                // A concurrent identical request won the
                                // key. Its receipt, which may be a success,
                                // is this request's answer, gated like any
                                // other replay.
                                Ok(Some((status_code, receipt))) => {
                                    return self
                                        .audited_replay(
                                            correlation,
                                            caller,
                                            grant,
                                            operation,
                                            status_code,
                                            receipt,
                                        )
                                        .await;
                                }
                                Ok(None) => {}
                                Err(
                                    failure @ (CommitError::KeyReused | CommitError::KeyExpired),
                                ) => {
                                    problem = problem_of(&failure);
                                    response = Unanswered::Unfinished(key_refusal_reason(&failure));
                                }
                                Err(failure) => {
                                    tracing::error!(%failure, "the refused attempt receipt could not be recorded");
                                }
                            }
                        }
                        Err(refused) => {
                            tracing::error!(error = %refused, "the refused attempt could not be recorded");
                        }
                    }
                }
                let record = match response {
                    Unanswered::Denied(reason) => audit_record(
                        &self.hasher,
                        &self.scheduling_id,
                        caller,
                        grant,
                        operation,
                        AuthorizationOutcome::Denied,
                        reason,
                    ),
                    Unanswered::Unfinished(reason) => audit_record(
                        &self.hasher,
                        &self.scheduling_id,
                        caller,
                        grant,
                        operation,
                        AuthorizationOutcome::Allowed,
                        "authorization.allowed",
                    )
                    .map(|record| unfinished_record(record, reason)),
                };
                self.record_refusal(correlation, record).await?;
                Err(ServiceError::Problem(problem))
            }
        }
    }

    /// Decode and load one stored cursor row. Binding to a listing is the
    /// caller's act: the availability walk reads the stored interval before
    /// it can compute the context it binds against.
    async fn stored_cursor(&self, encoded: &str) -> Result<StoredCursor, ServiceError> {
        let cursor_id = decode_cursor(encoded)?;
        let stored = self
            .store
            .cursor(cursor_id)
            .await?
            .ok_or(CursorError::Invalid)?;
        Ok(StoredCursor {
            cursor_id,
            context: stored["context"].as_str().unwrap_or_default().to_owned(),
            position: stored["position"].clone(),
            expires_at: serde_json::from_value(stored["expiresAt"].clone())
                .map_err(|_| CursorError::Invalid)?,
        })
    }

    async fn resolve_position(
        &self,
        cursor: Option<&str>,
        context: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ListingPosition>, ServiceError> {
        let Some(encoded) = cursor else {
            return Ok(None);
        };
        let stored = self.stored_cursor(encoded).await?;
        Ok(Some(bind_stored(&stored, context, now)?))
    }

    async fn mint_cursor(
        &self,
        context: &str,
        position: &ListingPosition,
        now: DateTime<Utc>,
    ) -> Result<String, ServiceError> {
        let cursor_id = Uuid::new_v4();
        self.store
            .insert_cursor(cursor_id, context, position.to_json(), cursor_expiry(now))
            .await?;
        Ok(encode_cursor(cursor_id))
    }
}

/// Decide whether one verified task grant is current at `now`, in Unix
/// seconds. Listed status authorities are authoritative for every source: a
/// grant without the signed subjects its status binding needs, or from a
/// source no authority is listed for, is refused and never reaches the
/// offline path. Without them, the offline path accepts a grant only while it
/// is unexpired with at most fifteen minutes left, and asks no authority.
async fn task_grant_verdict(
    status: Option<&TaskGrantStatusRegistry>,
    subjects: Option<std::collections::BTreeMap<String, Value>>,
    grant: &GrantClaims,
    now: u64,
) -> Result<(), TaskGrantError> {
    match status {
        Some(status) => match subjects
            .and_then(|subjects| TaskGrantStatusBinding::from_verified(grant, subjects).ok())
        {
            Some(binding) => status.check(&binding).await,
            None => Err(TaskGrantError::Refused),
        },
        None if grant.exp() > now && grant.exp() - now <= OFFLINE_TASK_GRANT_REMAINING_SECONDS => {
            Ok(())
        }
        None => Err(TaskGrantError::Refused),
    }
}

/// The minted-claim projection each commitment answer carries.
pub trait FromMinted {
    fn from_minted(outcome: CommitOutcome) -> Self;
}

impl FromMinted for ClaimRow {
    fn from_minted(outcome: CommitOutcome) -> Self {
        match outcome {
            CommitOutcome::Booking(claim) | CommitOutcome::Hold(claim) => claim,
            CommitOutcome::Cancelled(claim) => claim,
            CommitOutcome::Attendance(_) => unreachable!("attendance is not a minted claim"),
            CommitOutcome::Released => unreachable!("a release is not a minted claim"),
            CommitOutcome::Replay { .. } => unreachable!("a replay is not a minted claim"),
        }
    }
}

impl FromMinted for AttendanceObservation {
    fn from_minted(outcome: CommitOutcome) -> Self {
        match outcome {
            CommitOutcome::Attendance(observation) => observation,
            _ => unreachable!("a non-attendance commitment is not an attendance answer"),
        }
    }
}

impl FromMinted for () {
    fn from_minted(outcome: CommitOutcome) -> Self {
        match outcome {
            CommitOutcome::Released => (),
            _ => unreachable!("a claim minting is not an empty answer"),
        }
    }
}

/// A stored success receipt carries the claim the first answer minted; the
/// replay answers with that same claim through the same projection, so a
/// retried request reads the original response, not a re-derivation. A
/// refusal receipt carries no claim and flows to the edge untouched.
fn claim_or_replay<T>(
    answer: CommitmentAnswer<ClaimRow>,
    project: impl FnOnce(&ClaimRow, Option<&Value>) -> T,
) -> CommitmentAnswer<T> {
    match answer {
        CommitmentAnswer::Minted(claim) => CommitmentAnswer::Minted(project(&claim, None)),
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => {
            if let Some(claim) = receipt
                .get("claim")
                .cloned()
                .and_then(|value| serde_json::from_value::<ClaimRow>(value).ok())
            {
                CommitmentAnswer::Minted(project(&claim, Some(&receipt)))
            } else {
                CommitmentAnswer::Replay {
                    status_code,
                    receipt,
                }
            }
        }
    }
}

fn validate_bundle_width(additional_allocations: usize) -> Result<(), ServiceError> {
    if additional_allocations > registry_scheduling_core::MAXIMUM_ADDITIONAL_ALLOCATIONS {
        return Err(ServiceError::Problem(ProblemCode::RequestUnprocessable));
    }
    Ok(())
}

/// The resolved supply an offering runs against, owned here and borrowed into
/// the store's context.
enum ResolvedSupply {
    ExactTime {
        exact: ExactTimeOffering,
        members: Vec<PoolMember>,
        open: Vec<CalendarInterval>,
        closures: Vec<CalendarInterval>,
    },
    Window {
        /// Every window the offering serves, in start order: the one it
        /// names, or each records-published window naming it.
        windows: Vec<PublishedWindow>,
        lead_time_minutes: u32,
        horizon_days: u32,
        channels: Vec<Channel>,
        open: Vec<CalendarInterval>,
        closures: Vec<CalendarInterval>,
    },
}

enum ResolvedRequestSupply<'p> {
    Exact(ResolvedExactBundle<'p>),
    Window(ResolvedSupply),
}

struct ResolvedExactBundleLine<'p> {
    requirement_id: String,
    offering: &'p OfferingPolicy,
    supply: ResolvedSupply,
    resource: Option<String>,
    stored_resource: bool,
    units: u32,
}

struct ResolvedExactBundle<'p> {
    lines: Vec<ResolvedExactBundleLine<'p>>,
}

impl ResolvedExactBundle<'_> {
    fn contexts(&self) -> Result<Vec<BundleSupplyLine<'_>>, ServiceError> {
        self.lines
            .iter()
            .map(|line| match &line.supply {
                ResolvedSupply::ExactTime {
                    exact,
                    members,
                    open,
                    closures,
                } => Ok(BundleSupplyLine {
                    requirement_id: line.requirement_id.clone(),
                    offering: line.offering,
                    exact,
                    members,
                    open,
                    closures,
                    resource: line.resource.as_deref(),
                    stored_resource: line.stored_resource,
                    units: line.units,
                }),
                ResolvedSupply::Window { .. } => {
                    Err(ServiceError::Problem(ProblemCode::RequestUnprocessable))
                }
            })
            .collect()
    }
}

impl ResolvedSupply {
    fn resolve(
        policy: &SchedulingPolicy,
        facts: &SchedulingFacts,
        offering: &OfferingPolicy,
    ) -> Result<Self, ServiceError> {
        // Every reference the policy names must exist in the live records.
        // A gap is operator state the caller cannot see or fix, disclosed as
        // no availability and logged for the operator.
        let operator_gap = |reference: &str| {
            tracing::error!(
                offering = %offering.id,
                reference,
                "the offering names a reference the records do not carry"
            );
            ServiceError::Problem(ProblemCode::ServiceUnavailable)
        };
        let location = facts
            .location(&offering.location)
            .ok_or_else(|| operator_gap(&offering.location))?;
        let exceptions: Vec<_> = facts
            .exceptions
            .iter()
            .filter(|exception| exception.location == offering.location)
            .map(|exception| exception.borrowed())
            .collect();
        match (&offering.exact_time, &offering.arrival) {
            (Some(exact), None) => {
                let pool = facts
                    .pool(&exact.pool)
                    .ok_or_else(|| operator_gap(&exact.pool))?;
                Ok(Self::ExactTime {
                    exact: exact.clone(),
                    members: pool.members.clone(),
                    open: location_open_intervals(
                        policy,
                        &offering.location,
                        &location.timezone,
                        &exceptions,
                    )?,
                    closures: location_closure_intervals(
                        facts,
                        &offering.location,
                        &location.timezone,
                    )?,
                })
            }
            (None, Some(arrival)) => {
                let windows = served_windows(facts, offering)?;
                Ok(Self::Window {
                    windows,
                    lead_time_minutes: arrival.lead_time_minutes,
                    horizon_days: arrival.horizon_days,
                    channels: policy.channels.clone(),
                    open: location_open_intervals(
                        policy,
                        &offering.location,
                        &location.timezone,
                        &exceptions,
                    )?,
                    closures: location_closure_intervals(
                        facts,
                        &offering.location,
                        &location.timezone,
                    )?,
                })
            }
            _ => Err(operator_gap("one scheduling mode")),
        }
    }

    /// The context a request starting at `start` runs against. A named
    /// window answers every start, so admission refuses a start that is not
    /// its own as it always has; an offering serving several windows answers
    /// with the one opening at `start`, or with none.
    fn context_at<'a>(
        &'a self,
        offering: &'a OfferingPolicy,
        start: DateTime<Utc>,
    ) -> Option<SupplyContext<'a>> {
        self.context_where(|windows| offering.arrival_window(windows, start))
    }

    /// The context a hold is confirmed under. A named window answers every
    /// hold, as it always has; an offering serving several windows answers
    /// with the window the hold occupies, which stays its identity even when
    /// the records move that window's start.
    fn context_for_hold(
        &self,
        offering: &OfferingPolicy,
        hold: &ClaimRow,
    ) -> Option<SupplyContext<'_>> {
        let names_one = offering
            .arrival
            .as_ref()
            .is_some_and(|arrival| arrival.window.is_some());
        self.context_where(|windows| {
            windows
                .iter()
                .find(|window| names_one || window.id == hold.supply_id)
        })
    }

    fn context_where<'a>(
        &'a self,
        pick: impl FnOnce(&'a [PublishedWindow]) -> Option<&'a PublishedWindow>,
    ) -> Option<SupplyContext<'a>> {
        match self {
            Self::ExactTime {
                exact,
                members,
                open,
                closures,
            } => Some(SupplyContext::ExactTime {
                exact,
                members,
                open,
                closures,
            }),
            Self::Window {
                windows,
                lead_time_minutes,
                horizon_days,
                channels,
                open,
                closures,
            } => pick(windows).map(|window| SupplyContext::Window {
                window,
                lead_time_minutes: *lead_time_minutes,
                horizon_days: *horizon_days,
                channels: channels.as_slice(),
                open,
                closures,
            }),
        }
    }
}

/// The refusal a start meets on an offering serving several windows when no
/// window opens at it: the same schedule refusal a named window gives a start
/// that is not its own, receipted and audited like any admission refusal.
fn no_window_at_start() -> CommitError {
    CommitError::Refused(registry_scheduling_core::AdmissionRefusal::ScheduleUnpublished)
}

/// Resolve every published window an arrival-window offering serves, in start
/// order: the window it names, bound as [`bound_window`] binds it, or each
/// records-published window naming the offering. A served window at another
/// location is an operator gap, never capacity a caller may consume.
fn served_windows(
    facts: &SchedulingFacts,
    offering: &OfferingPolicy,
) -> Result<Vec<PublishedWindow>, ServiceError> {
    if let Some(named) = offering
        .arrival
        .as_ref()
        .and_then(|arrival| arrival.window.as_deref())
    {
        return Ok(vec![bound_window(facts, offering, named)?.clone()]);
    }
    let mut windows: Vec<PublishedWindow> =
        offering.served_windows(&facts.windows).cloned().collect();
    if let Some(window) = windows
        .iter()
        .find(|window| window.location != offering.location)
    {
        tracing::error!(
            offering = %offering.id,
            reference = %window.id,
            "the window record is not bound to the offering and location"
        );
        return Err(ServiceError::Problem(ProblemCode::ServiceUnavailable));
    }
    windows.sort_by_key(|window| window.start);
    Ok(windows)
}

/// Resolve a published window only when its operator record belongs to the
/// offering and location whose authority the service checked. A malformed or
/// stale records set is an operator gap, never capacity a caller may consume.
fn bound_window<'a>(
    facts: &'a SchedulingFacts,
    offering: &OfferingPolicy,
    reference: &str,
) -> Result<&'a PublishedWindow, ServiceError> {
    let window = facts.window(reference).ok_or_else(|| {
        tracing::error!(
            offering = %offering.id,
            reference,
            "the offering names a window the records do not carry"
        );
        ServiceError::Problem(ProblemCode::ServiceUnavailable)
    })?;
    if window.offering != offering.id || window.location != offering.location {
        tracing::error!(
            offering = %offering.id,
            reference,
            "the window record is not bound to the offering and location"
        );
        return Err(ServiceError::Problem(ProblemCode::ServiceUnavailable));
    }
    Ok(window)
}

/// The exact-time availability walk: one entry per grid slot that lies inside
/// the effective openings, inside the booking horizon, and that at least one
/// available, capable member can still serve.
///
/// `open` is the effective-open truth: closures already removed from it, and
/// an authorized reopening already restored into it. Filtering by raw
/// closures again here would strike out the time a reopening put back, so
/// discovery and admission would disagree; they read the same intervals
/// instead.
#[allow(clippy::too_many_arguments)]
fn exact_time_slots(
    exact: &ExactTimeOffering,
    members: &[PoolMember],
    requires_capabilities: &[String],
    open: &[CalendarInterval],
    snapshot: &LedgerSnapshot,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Vec<AvailabilityEntry> {
    let duration = TimeDelta::minutes(i64::from(exact.duration_minutes));
    let increment = TimeDelta::minutes(i64::from(exact.start_increment_minutes).max(1));
    let earliest = saturating_later(now, TimeDelta::minutes(i64::from(exact.lead_time_minutes)));
    let latest = saturating_later(now, TimeDelta::days(i64::from(exact.horizon_days)));
    let standing: Vec<_> = snapshot
        .claims
        .iter()
        .map(|claim| StandingAllocation {
            reservation_id: claim.id.clone(),
            resource_id: claim.supply_id.clone(),
            interval: AllocationInterval {
                start: claim.start,
                end: claim.end,
            },
            units: claim.units,
        })
        .collect();
    let mut entries = Vec::new();
    for interval in open {
        // Slots anchor on each published opening's own start. Jump directly
        // to the first grid point in the requested/horizon intersection so a
        // short page never walks years of an otherwise valid pattern.
        let lower = interval.start.max(from).max(earliest);
        let delta_seconds = (lower - interval.start).num_seconds().max(0);
        let increment_seconds = increment.num_seconds();
        let steps = (delta_seconds + increment_seconds - 1) / increment_seconds;
        let Some(mut slot_start) = interval
            .start
            .checked_add_signed(TimeDelta::seconds(steps.saturating_mul(increment_seconds)))
        else {
            continue;
        };
        while slot_start + duration <= interval.end && slot_start < to && slot_start <= latest {
            let slot_end = slot_start + duration;
            let occupied_start =
                slot_start - TimeDelta::minutes(i64::from(exact.buffer_before_minutes));
            let occupied_end = slot_end + TimeDelta::minutes(i64::from(exact.buffer_after_minutes));
            let coverage_fits = exact.opening_coverage
                == registry_scheduling_core::OpeningCoverage::ServiceInterval
                || (interval.start <= occupied_start && occupied_end <= interval.end);
            let remaining: Vec<u32> = members
                .iter()
                .filter(|member| member.available_during(occupied_start, occupied_end))
                .filter(|member| member.serves(requires_capabilities))
                .map(|member| {
                    let occupied = registry_scheduling_core::maximum_concurrent_units(
                        &member.resource_id,
                        &AllocationInterval {
                            start: occupied_start,
                            end: occupied_end,
                        },
                        &standing,
                        None,
                    )
                    .expect("bounded positive ledger allocations produce coherent occupancy");
                    member.capacity_units.saturating_sub(occupied)
                })
                .filter(|remaining| *remaining > 0)
                .collect();
            let free = remaining.len();
            let available_units = remaining.iter().copied().fold(0_u32, u32::saturating_add);
            if coverage_fits && free > 0 {
                entries.push(AvailabilityEntry::Slot {
                    start: slot_start,
                    end: slot_end,
                    free: u32::try_from(free).unwrap_or(u32::MAX),
                    available_units: Some(available_units),
                });
            }
            slot_start += increment;
            if slot_start >= interval.end {
                break;
            }
        }
    }
    entries.sort_by_key(entry_instant);
    entries.dedup_by_key(|entry| entry_instant(entry));
    entries
}

/// The arrival-window availability walk: one entry per published window in
/// range with units left, after lead time and inside the horizon.
#[allow(clippy::too_many_arguments)]
fn window_entries(
    window: &PublishedWindow,
    snapshot: &LedgerSnapshot,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
    lead_time_minutes: u32,
    horizon_days: u32,
    open: &[CalendarInterval],
) -> Vec<AvailabilityEntry> {
    let consumed: u32 = snapshot.claims.iter().map(|claim| claim.units).sum();
    let remaining = window.units.saturating_sub(consumed);
    let earliest = saturating_later(now, TimeDelta::minutes(i64::from(lead_time_minutes)));
    let latest = saturating_later(now, TimeDelta::days(i64::from(horizon_days)));
    let in_range = window.start >= from && window.start < to;
    let in_horizon = window.start >= earliest && window.start <= latest;
    let is_open = open
        .iter()
        .any(|interval| interval.start <= window.start && window.end <= interval.end);
    if in_range && in_horizon && is_open && remaining > 0 {
        vec![AvailabilityEntry::Window {
            window: window.id.clone(),
            start: window.start,
            end: window.end,
            remaining,
            // The caller's channel slice is a booking-time fact; a public
            // availability read carries no channel.
            channel_remaining: None,
        }]
    } else {
        Vec::new()
    }
}

fn start_is_within_horizon(
    start: DateTime<Utc>,
    now: DateTime<Utc>,
    lead_time_minutes: u32,
    horizon_days: u32,
) -> bool {
    let lead = start.signed_duration_since(now);
    lead >= TimeDelta::minutes(i64::from(lead_time_minutes))
        && lead <= TimeDelta::days(i64::from(horizon_days))
}

fn party_fits_exact_time(party: PartyCounts, exact: &ExactTimeOffering) -> bool {
    party.is_coherent()
        && party.recipients <= exact.maximum_recipients
        && (!exact.party_counts.is_required() || party.recipients > 0)
}

/// `instant` moved later by `delta`, or the last representable instant when
/// the sum would leave the calendar. A bound past representable time bounds
/// nothing, so saturating keeps its meaning where the sum would panic: policy
/// validation accepts any nonzero `horizonDays`, and a caller may name a
/// range end at the edge of the calendar.
fn saturating_later(instant: DateTime<Utc>, delta: TimeDelta) -> DateTime<Utc> {
    instant
        .checked_add_signed(delta)
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// `instant` moved earlier by `delta`, or the first representable instant.
fn saturating_earlier(instant: DateTime<Utc>, delta: TimeDelta) -> DateTime<Utc> {
    instant
        .checked_sub_signed(delta)
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn entry_instant(entry: &AvailabilityEntry) -> DateTime<Utc> {
    match entry {
        AvailabilityEntry::Slot { start, .. } | AvailabilityEntry::Window { start, .. } => *start,
    }
}

fn page_limit(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAXIMUM_PAGE_LIMIT)
}

/// The `after` id of a position a by-id listing carries, or the invalid-cursor
/// refusal for a foreign position shape.
fn id_position(position: Option<ListingPosition>) -> Result<Option<String>, ServiceError> {
    match position {
        Some(ListingPosition::AfterId { last_id }) => Ok(Some(last_id)),
        Some(_) => Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
        None => Ok(None),
    }
}

trait LastId {
    fn last_id(&self) -> String;
}

macro_rules! last_id_via {
    ($name:ident) => {
        impl LastId for $name {
            fn last_id(&self) -> String {
                self.id.clone()
            }
        }
    };
}
last_id_via!(ServiceDocument);
last_id_via!(OfferingDocument);

impl LastId for ResourceDocument {
    fn last_id(&self) -> String {
        self.resource_id.clone()
    }
}

impl LastId for registry_scheduling_core::LocationDocument {
    fn last_id(&self) -> String {
        self.location_id.clone()
    }
}

fn position_of_last_id<T: LastId>(items: &[T]) -> ListingPosition {
    ListingPosition::AfterId {
        last_id: items.last().expect("a limited page is not empty").last_id(),
    }
}

async fn page_of<T: LastId>(
    service: &SchedulingService,
    items: Vec<T>,
    position: Option<ListingPosition>,
    limit: usize,
    context: &str,
    now: DateTime<Utc>,
) -> Result<PageDocument<T>, ServiceError> {
    let after = match position {
        Some(ListingPosition::AfterId { last_id }) => Some(last_id),
        Some(_) => return Err(ServiceError::Problem(ProblemCode::CursorInvalid)),
        None => None,
    };
    let selected: Vec<_> = items
        .into_iter()
        .filter(|item| after.as_ref().is_none_or(|after| &item.last_id() > after))
        .collect();
    let more = selected.len() > limit;
    let page: Vec<_> = selected.into_iter().take(limit).collect();
    let next_cursor = if more {
        Some(
            service
                .mint_cursor(context, &position_of_last_id(&page), now)
                .await?,
        )
    } else {
        None
    };
    Ok(PageDocument {
        items: page,
        next_cursor,
    })
}

/// One stored history row as its published document. Every field is strict:
/// a row that does not carry the shape the store writes is corruption, and
/// the caller sees no part of it.
fn history_entry(row: &Value) -> Result<AppointmentHistoryEntryDocument, ServiceError> {
    let corrupt = || ServiceError::internal("a stored history row is corrupt");
    Ok(AppointmentHistoryEntryDocument {
        event_id: row["eventId"].as_str().ok_or_else(corrupt)?.to_owned(),
        kind: row["kind"].as_str().ok_or_else(corrupt)?.to_owned(),
        revision: u64::try_from(row["revision"].as_i64().ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?,
        occurred_at: serde_json::from_value(row["occurredAt"].clone()).map_err(|_| corrupt())?,
        actor: row["actor"].as_str().map(str::to_owned),
        detail: row.get("detail").cloned().unwrap_or(Value::Null),
    })
}

fn hold_document(
    claim: &ClaimRow,
    policy: &SchedulingPolicy,
    policy_revision: u64,
    receipt: Option<&Value>,
) -> registry_scheduling_core::HoldDocument {
    registry_scheduling_core::HoldDocument {
        hold_id: claim.claim_id.to_string(),
        offering: claim.offering.clone(),
        start: claim.displayed_start,
        end: claim.displayed_end,
        resource: projected_resource(claim, policy, receipt),
        units: u32::try_from(claim.units).unwrap_or(u32::MAX),
        allocations: claim.allocations.clone(),
        party: claim.party,
        manager: projected_manager(claim, receipt),
        party_references: claim.party_references.clone(),
        expires_at: claim.hold_expires_at.unwrap_or(claim.created_at),
        policy_revision: projected_policy_revision(policy_revision, receipt),
        external_references: claim.external_references.clone(),
    }
}

fn appointment_document(
    claim: &ClaimRow,
    policy: &SchedulingPolicy,
    policy_revision: u64,
    receipt: Option<&Value>,
) -> AppointmentDocument {
    AppointmentDocument {
        appointment_id: claim.claim_id.to_string(),
        offering: claim.offering.clone(),
        start: claim.displayed_start,
        end: claim.displayed_end,
        resource: projected_resource(claim, policy, receipt),
        units: u32::try_from(claim.units).unwrap_or(u32::MAX),
        allocations: claim.allocations.clone(),
        party: claim.party,
        manager: projected_manager(claim, receipt),
        party_references: claim.party_references.clone(),
        channel: claim.channel.clone(),
        revision: u64::try_from(claim.revision).unwrap_or(u64::MAX),
        state: if claim.state == crate::store::ClaimState::Cancelled {
            AppointmentStateDocument::Cancelled
        } else {
            AppointmentStateDocument::Confirmed
        },
        policy_revision: projected_policy_revision(policy_revision, receipt),
        created_at: claim.created_at,
        cancelled_at: claim.closed_at,
        external_references: claim.external_references.clone(),
        attendance: None,
    }
}

fn projected_policy_revision(current: u64, receipt: Option<&Value>) -> u64 {
    receipt
        .and_then(|value| value.get("policyRevision"))
        .and_then(Value::as_i64)
        .and_then(|revision| u64::try_from(revision).ok())
        .unwrap_or(current)
}

fn projected_manager(claim: &ClaimRow, receipt: Option<&Value>) -> Option<ManagerSelection> {
    if receipt
        .and_then(|value| value.get("manager"))
        .and_then(Value::as_str)
        == Some("schedulingManager")
        || claim.source_manager.is_some()
    {
        Some(ManagerSelection::SchedulingManager)
    } else {
        None
    }
}

fn projected_resource(
    claim: &ClaimRow,
    policy: &SchedulingPolicy,
    receipt: Option<&Value>,
) -> Option<String> {
    match receipt.and_then(|value| value.get("resource")) {
        Some(Value::String(resource)) => Some(resource.clone()),
        Some(Value::Null) => None,
        _ => claim
            .supply_id_is_member(policy)
            .then(|| claim.supply_id.clone()),
    }
}

impl ClaimRow {
    /// Whether the claim's supply id names a pool member (an exact-time
    /// booking) rather than a window.
    ///
    /// The ledger keeps one supply column for both: an exact-time claim
    /// occupies the pool member it was assigned, and a window claim occupies
    /// the window itself. Only the offering's mode says which of the two the
    /// column holds, so an offering the policy no longer carries names no
    /// member: a supply id that cannot be shown to be one is not published
    /// through a field that promises one.
    fn supply_id_is_member(&self, policy: &SchedulingPolicy) -> bool {
        policy
            .offering(&self.offering)
            .is_some_and(|offering| offering.mode == SchedulingMode::ExactTime)
    }
}

/// The `response` a commitment that is not answered by a success or a replay
/// writes: a refusal the ledger or the permission check decided, or the
/// closed reason a commitment nothing decided did not finish.
#[derive(Clone, Copy)]
enum Unanswered {
    Denied(&'static str),
    Unfinished(&'static str),
}

/// The closed reason an idempotency key refusal records.
fn key_refusal_reason(error: &CommitError) -> &'static str {
    if matches!(error, CommitError::KeyExpired) {
        "idempotency.expired"
    } else {
        "idempotency.key-reused"
    }
}

fn problem_of(error: &CommitError) -> ProblemCode {
    match error {
        CommitError::Store(_) | CommitError::Query(_) | CommitError::Hooks(_) => {
            ProblemCode::ServiceUnavailable
        }
        CommitError::Refused(refusal) => refusal.public_code(),
        CommitError::KeyReused => ProblemCode::IdempotencyKeyReused,
        CommitError::KeyExpired => ProblemCode::IdempotencyExpired,
        CommitError::HoldCeiling => ProblemCode::CapacityExhausted,
        CommitError::Unauthorized => ProblemCode::OperationNotAuthorized,
        CommitError::RevisionMismatch => ProblemCode::RevisionMismatch,
        CommitError::ObservationInFuture => ProblemCode::RequestUnprocessable,
        CommitError::CutoffPassed => ProblemCode::CancellationCutoffPassed,
        // Nothing was decided: the caller retries against the current records.
        CommitError::FactsStale => ProblemCode::ServiceUnavailable,
        // The caller retries under the same key, which replays the receipt
        // if the commit took effect.
        CommitError::Unacknowledged => ProblemCode::ServiceUnavailable,
    }
}

/// The decision a stored receipt carries, as its replay's `response` entry
/// records it. A success receipt was allowed. A refusal receipt was written
/// only for a decision the ledger took, so it keeps the reason its first
/// answer recorded: a lapsed grant is `authorization.refused`, every other
/// ledger refusal `authorization.profile`.
fn replayed_decision(status_code: u16, receipt: &Value) -> (AuthorizationOutcome, &'static str) {
    if status_code < 400 {
        return (AuthorizationOutcome::Allowed, "authorization.allowed");
    }
    let unauthorized =
        receipt["problem"]["code"].as_str() == Some(ProblemCode::OperationNotAuthorized.code());
    if unauthorized {
        (AuthorizationOutcome::Denied, "authorization.refused")
    } else {
        (AuthorizationOutcome::Denied, "authorization.profile")
    }
}

/// The stored body a replayed refusal answers with: the pinned problem
/// without a trace id, so the edge stamps the answering request's own trace.
fn problem_receipt(problem: ProblemCode) -> Value {
    json!({
        "problem": {
            "type": type_uri(problem.code()),
            "title": problem.title(),
            "status": problem.http_status(),
            "detail": problem.detail(),
            "code": problem.code(),
        }
    })
}

fn canonical_hash(value: &Value) -> Result<String, ServiceError> {
    let canonical = canonicalize_json(value)
        .map_err(|_| ServiceError::internal("a request body could not be canonicalized"))?;
    let digest = Sha256::digest(&canonical);
    Ok(format!("sha256:{}", hex(&digest)))
}

fn busy_source_audit_response(mut record: Value, outcome: &str, reason: &str) -> Value {
    if let Some(fields) = record.as_object_mut() {
        fields.insert("outcome".to_owned(), Value::String(outcome.to_owned()));
        fields.insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    record
}

#[allow(clippy::too_many_arguments)]
fn busy_source_audit_result(
    mut record: Value,
    outcome: &str,
    revision: u64,
    added: u64,
    changed: u64,
    deleted: u64,
    impacts: &crate::source_busy::BusyImpactSummary,
) -> Value {
    if let Some(fields) = record.as_object_mut() {
        fields.insert("outcome".to_owned(), Value::String(outcome.to_owned()));
        fields.insert("reason".to_owned(), Value::String("allowed".to_owned()));
        fields.insert("revision".to_owned(), json!(revision));
        fields.insert("added".to_owned(), json!(added));
        fields.insert("changed".to_owned(), json!(changed));
        fields.insert("deleted".to_owned(), json!(deleted));
        fields.insert("impactTotal".to_owned(), json!(impacts.total));
        fields.insert("impactTruncated".to_owned(), json!(impacts.truncated));
    }
    record
}

fn busy_source_audit_reason(error: &BusyStoreError) -> &'static str {
    match error {
        BusyStoreError::RevisionMismatch { .. } => "revision.mismatch",
        BusyStoreError::CoverageBoundary => "coverage.boundary",
        BusyStoreError::ObservationConflict => "observation.conflict",
        BusyStoreError::RecoveryUnavailable => "recovery.unavailable",
        BusyStoreError::ResourceMissing => "resource.missing",
        BusyStoreError::AuditUnavailable => "audit.unavailable",
        BusyStoreError::Query(_) | BusyStoreError::Store(_) => "store.unavailable",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}

/// The attributable record of a refusal decided before any grant was
/// resolved. The caller authenticated, so there is a principal to attribute
/// the attempt to, but no grant, approver, or purpose exists to record and
/// none is invented.
///
/// The shape still demands a client. Without a grant the deployment verified
/// no client identity, so the field carries the credential's issuer under the
/// issuer reference class, and the absent grant pseudonym is what tells a
/// reader of the audit entries which of the two it is looking at.
fn grantless_refusal_record(
    hasher: &AuditKeyHasher,
    scope: &str,
    caller: &Caller,
    operation: &str,
) -> Result<Value, ServiceError> {
    let issuer = hasher
        .audit_reference_hash(ISSUER_CLASS, scope, &caller.issuer)
        .map_err(|_| ServiceError::internal("an audit reference could not be pseudonymized"))?;
    let event = AuthorizationAuditEvent::denied_without_purpose(
        caller.actor_kind.clone(),
        caller.actor_pseudonym(hasher, scope)?,
        issuer,
        None,
        None,
        operation,
        "authorization.no-grant",
    )
    .map_err(|_| ServiceError::internal("the authorization audit event is not publishable"))?;
    serde_json::to_value(event)
        .map_err(|_| ServiceError::internal("the authorization audit event is not publishable"))
}

/// The attributable authorization record of one commitment, with the
/// principal, client, grant, and approver pseudonymized and the purpose
/// recorded as presence only, the way the stack's other runtimes publish it.
#[allow(clippy::too_many_arguments)]
fn audit_record(
    hasher: &AuditKeyHasher,
    scope: &str,
    caller: &Caller,
    grant: &GrantClaims,
    operation: &str,
    outcome: AuthorizationOutcome,
    reason: &str,
) -> Result<Value, ServiceError> {
    let pseudonym = |class: &str, value: &str| -> Result<String, ServiceError> {
        hasher
            .audit_reference_hash(class, scope, value)
            .map_err(|_| ServiceError::internal("an audit reference could not be pseudonymized"))
    };
    let event = AuthorizationAuditEvent::new(
        caller.actor_kind.clone(),
        pseudonym("scheduling-principal-v1", grant.principal())?,
        pseudonym("scheduling-client-v1", grant.client())?,
        Some(pseudonym("scheduling-grant-v1", grant.id())?),
        Some(pseudonym("scheduling-approver-v1", grant.approver())?),
        grant.purpose(),
        operation,
        outcome,
        reason,
    )
    .map_err(|_| ServiceError::internal("the authorization audit event is not publishable"))?;
    let mut value = serde_json::to_value(event)
        .map_err(|_| ServiceError::internal("the authorization audit event is not publishable"))?;
    let Some(object) = value.as_object_mut() else {
        return Err(ServiceError::internal(
            "the authorization audit event is not an object",
        ));
    };
    // Purpose presence is recorded, never the purpose value.
    object.remove("purpose");
    value["sourceIssuer"] = json!(grant.source_issuer());
    value["expiresAt"] = json!(grant.exp());
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn bundle_width_is_bounded_before_service_allocation() {
        assert!(
            validate_bundle_width(registry_scheduling_core::MAXIMUM_ADDITIONAL_ALLOCATIONS).is_ok()
        );
        assert!(matches!(
            validate_bundle_width(registry_scheduling_core::MAXIMUM_ADDITIONAL_ALLOCATIONS + 1),
            Err(ServiceError::Problem(ProblemCode::RequestUnprocessable))
        ));
    }

    #[test]
    fn source_busy_audit_records_only_counts_not_impact_details() {
        let record = json!({
            "event": "source-busy.apply",
            "actor": "pseudonym",
            "requestDigest": "sha256:digest",
        });
        let impacts = crate::source_busy::BusyImpactSummary {
            total: 1,
            details_available: true,
            truncated: false,
            items: vec![crate::source_busy::BusyCommitmentImpact {
                kind: "booking".to_owned(),
                resource: "staff-a".to_owned(),
                occupied_start: Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
                occupied_end: Utc.with_ymd_and_hms(2026, 10, 23, 10, 0, 0).unwrap(),
            }],
        };
        let audited = busy_source_audit_result(record, "applied", 2, 1, 0, 0, &impacts);
        assert_eq!(audited["impactTotal"], 1);
        assert!(audited.get("items").is_none());
        assert!(audited.get("resource").is_none());
        assert!(audited.get("occupiedStart").is_none());
    }

    fn interval(start_hour: u32, end_hour: u32) -> CalendarInterval {
        let day = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
        CalendarInterval {
            start: day + TimeDelta::hours(i64::from(start_hour)),
            end: day + TimeDelta::hours(i64::from(end_hour)),
        }
    }

    fn exact() -> ExactTimeOffering {
        ExactTimeOffering {
            party_counts: Default::default(),
            duration_minutes: 30,
            duration_selection: None,
            opening_coverage: registry_scheduling_core::OpeningCoverage::ServiceInterval,
            allow_resource_selection: false,
            buffer_before_minutes: 5,
            buffer_after_minutes: 5,
            lead_time_minutes: 60,
            horizon_days: 30,
            pool: "north-stations".to_owned(),
            start_increment_minutes: 30,
            maximum_recipients: 2,
        }
    }

    fn members(count: usize) -> Vec<PoolMember> {
        (1..=count)
            .map(|index| PoolMember {
                resource_id: format!("station-{index}"),
                capabilities: Vec::new(),
                available: true,
                capacity_units: 1,
                availability: None,
            })
            .collect()
    }

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 5, hour, minute, 0).unwrap()
    }

    fn booking_of(
        id: &str,
        supply_id: &str,
        start: u32,
        end: u32,
    ) -> registry_scheduling_core::LedgerClaim {
        registry_scheduling_core::LedgerClaim {
            id: id.to_owned(),
            offering: "registry-update-30".to_owned(),
            supply_id: supply_id.to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start: at(start, 50),
            end: at(end, 10),
            units: 1,
            duplicate_key: None,
            expires_at: None,
        }
    }

    fn window_offering() -> OfferingPolicy {
        OfferingPolicy {
            id: "review-arrivals".to_owned(),
            service: "registry-review".to_owned(),
            label: "Review arrivals".to_owned(),
            mode: SchedulingMode::ArrivalWindow,
            location: "north-counter".to_owned(),
            because: "test".to_owned(),
            exact_time: None,
            arrival: Some(registry_scheduling_core::ArrivalOffering {
                window: Some("morning-arrivals".to_owned()),
                lead_time_minutes: 60,
                horizon_days: 30,
            }),
            cancellation_cutoff_minutes: 240,
            reminders: Vec::new(),
            duplicate_active_key: None,
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        }
    }

    fn window_facts() -> SchedulingFacts {
        SchedulingFacts {
            windows: vec![PublishedWindow {
                id: "morning-arrivals".to_owned(),
                revision: 1,
                offering: "review-arrivals".to_owned(),
                location: "north-counter".to_owned(),
                start: at(2, 0),
                end: at(4, 0),
                units: 2,
                units_policy: registry_scheduling_core::RequiredUnitsPolicy::Fixed {
                    units: 1,
                    because: "test".to_owned(),
                },
                subquotas: Vec::new(),
                leftover: None,
                staffing: None,
                resources: Vec::new(),
                because: "test".to_owned(),
            }],
            ..SchedulingFacts::default()
        }
    }

    #[test]
    fn a_window_resolves_only_for_its_own_offering_and_location() {
        let offering = window_offering();
        let mut facts = window_facts();
        assert!(bound_window(&facts, &offering, "morning-arrivals").is_ok());

        facts.windows[0].offering = "other-arrivals".to_owned();
        assert!(matches!(
            bound_window(&facts, &offering, "morning-arrivals"),
            Err(ServiceError::Problem(ProblemCode::ServiceUnavailable))
        ));

        facts.windows[0].offering = offering.id.clone();
        facts.windows[0].location = "south-counter".to_owned();
        assert!(matches!(
            bound_window(&facts, &offering, "morning-arrivals"),
            Err(ServiceError::Problem(ProblemCode::ServiceUnavailable))
        ));
    }

    #[test]
    fn slots_walk_the_grid_inside_the_opening() {
        let now = at(0, 0);
        let entries = exact_time_slots(
            &exact(),
            &members(2),
            &[],
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            now,
        );
        let starts: Vec<_> = entries.iter().map(entry_instant).collect();
        assert_eq!(starts, vec![at(2, 0), at(2, 30), at(3, 0), at(3, 30)]);
        assert!(entries.iter().all(|entry| match entry {
            AvailabilityEntry::Slot { free, .. } => *free == 2,
            _ => false,
        }));
    }

    #[test]
    fn a_slot_the_lead_time_excludes_is_not_listed() {
        let now = at(2, 15);
        let entries = exact_time_slots(
            &exact(),
            &members(1),
            &[],
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            now,
        );
        // The earliest bookable start is 03:15 on the grid, so 03:30 is first.
        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![at(3, 30)]
        );
    }

    /// Policy validation accepts any nonzero `horizonDays`, and the largest
    /// reaches past the last instant the calendar can represent. A horizon
    /// beyond representable time bounds nothing, so the walk lists what the
    /// opening and the requested range allow rather than panicking.
    #[test]
    fn an_exact_time_horizon_past_representable_time_bounds_nothing() {
        let mut exact = exact();
        exact.horizon_days = u32::MAX;
        let entries = exact_time_slots(
            &exact,
            &members(1),
            &[],
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![at(2, 0), at(2, 30), at(3, 0), at(3, 30)]
        );
    }

    /// The same boundary for an arrival window: the largest accepted horizon
    /// lists the window instead of panicking the availability request.
    #[test]
    fn a_window_horizon_past_representable_time_bounds_nothing() {
        let window = window_facts().windows.remove(0);
        let entries = window_entries(
            &window,
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
            60,
            u32::MAX,
            &[interval(0, 6)],
        );
        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![at(2, 0)]
        );
    }

    #[test]
    fn a_booking_occupying_a_member_reduces_its_free_count() {
        let snapshot = LedgerSnapshot {
            claims: vec![booking_of("booking-1", "station-1", 2, 3)],
        };
        let entries = exact_time_slots(
            &exact(),
            &members(2),
            &[],
            &[interval(2, 4)],
            &snapshot,
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        let by_start = |start: DateTime<Utc>| {
            entries
                .iter()
                .find(|entry| entry_instant(entry) == start)
                .expect("the slot is listed")
        };
        match by_start(at(3, 0)) {
            AvailabilityEntry::Slot { free, .. } => assert_eq!(*free, 1),
            _ => panic!("expected a slot"),
        }
        match by_start(at(2, 0)) {
            AvailabilityEntry::Slot { free, .. } => assert_eq!(*free, 2),
            _ => panic!("expected a slot"),
        }
    }

    #[test]
    fn a_slot_reports_total_fungible_units_across_free_members() {
        let mut supply = members(2);
        for member in &mut supply {
            member.capacity_units = 2;
        }
        let entries = exact_time_slots(
            &exact(),
            &supply,
            &[],
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        let first = entries.first().expect("the slot is available");
        assert!(matches!(
            first,
            AvailabilityEntry::Slot {
                free: 2,
                available_units: Some(4),
                ..
            }
        ));
    }

    #[test]
    fn physical_preview_horizon_is_inclusive() {
        let now = at(0, 0);
        assert!(start_is_within_horizon(
            now + TimeDelta::days(30),
            now,
            60,
            30,
        ));
        assert!(!start_is_within_horizon(
            now + TimeDelta::minutes(59),
            now,
            60,
            30,
        ));
        assert!(!start_is_within_horizon(
            now + TimeDelta::days(30) + TimeDelta::seconds(1),
            now,
            60,
            30,
        ));
    }

    #[test]
    fn physical_preview_party_must_fit_each_offering() {
        let mut policy = exact();
        policy.maximum_recipients = 2;
        assert!(party_fits_exact_time(
            PartyCounts {
                recipients: 2,
                attendees: 3,
            },
            &policy,
        ));
        assert!(!party_fits_exact_time(
            PartyCounts {
                recipients: 3,
                attendees: 3,
            },
            &policy,
        ));
        assert!(!party_fits_exact_time(
            PartyCounts {
                recipients: 2,
                attendees: 1,
            },
            &policy,
        ));
    }

    #[test]
    fn slots_follow_the_effective_openings_a_reopening_restored() {
        // The openings are the effective-open truth: a closure that an
        // authorized reopening partly restores has already been subtracted
        // and added back here, so the walk does not filter by raw closures
        // again and strike out the restored time.
        let entries = exact_time_slots(
            &exact(),
            &members(1),
            &[],
            &[
                interval(2, 3),
                CalendarInterval {
                    start: at(3, 30),
                    end: at(4, 0),
                },
            ],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![at(2, 0), at(2, 30), at(3, 30)]
        );
    }

    #[test]
    fn a_slot_without_a_free_capable_member_is_not_availability() {
        let capable = [PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: vec!["interpreter".to_owned()],
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let requires = vec!["interpreter".to_owned()];
        // Only an incapable member is free: the slot is not listed, because
        // admission would refuse every start it advertised.
        let entries = exact_time_slots(
            &exact(),
            &members(1),
            &requires,
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert!(entries.is_empty());
        // One capable member among two: the free count names only it.
        let mut mixed = members(2);
        mixed.extend_from_slice(&capable);
        let entries = exact_time_slots(
            &exact(),
            &mixed,
            &requires,
            &[interval(2, 4)],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert!(entries.iter().all(|entry| match entry {
            AvailabilityEntry::Slot { free, .. } => *free == 1,
            _ => false,
        }));
    }

    #[test]
    fn a_fully_occupied_slot_is_not_availability() {
        let snapshot = LedgerSnapshot {
            claims: vec![
                booking_of("booking-1", "station-1", 2, 3),
                booking_of("booking-2", "station-2", 2, 3),
            ],
        };
        let entries = exact_time_slots(
            &exact(),
            &members(2),
            &[],
            &[interval(2, 4)],
            &snapshot,
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert!(entries.iter().all(|entry| entry_instant(entry) != at(3, 0)));
    }

    #[test]
    fn slots_anchor_on_each_opening_not_a_global_grid() {
        // Two openings whose starts are off each other's grid: each anchors
        // its own slots.
        let entries = exact_time_slots(
            &exact(),
            &members(1),
            &[],
            &[
                interval(2, 3),
                CalendarInterval {
                    start: at(3, 15),
                    end: at(4, 15),
                },
            ],
            &LedgerSnapshot { claims: Vec::new() },
            at(1, 0),
            at(5, 0),
            at(0, 0),
        );
        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![at(2, 0), at(2, 30), at(3, 15), at(3, 45)]
        );
    }

    #[test]
    fn slots_jump_to_the_requested_part_of_a_long_opening() {
        let opening = CalendarInterval {
            start: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2035, 12, 31, 0, 0, 0).unwrap(),
        };
        let now = Utc.with_ymd_and_hms(2035, 12, 1, 0, 0, 0).unwrap();
        let from = Utc.with_ymd_and_hms(2035, 12, 2, 10, 7, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2035, 12, 2, 11, 0, 0).unwrap();
        let entries = exact_time_slots(
            &exact(),
            &members(1),
            &[],
            &[opening],
            &LedgerSnapshot { claims: Vec::new() },
            from,
            to,
            now,
        );

        assert_eq!(
            entries.iter().map(entry_instant).collect::<Vec<_>>(),
            vec![Utc.with_ymd_and_hms(2035, 12, 2, 10, 30, 0).unwrap()]
        );
    }

    #[test]
    fn page_limits_clamp_to_the_published_bound() {
        assert_eq!(page_limit(None), DEFAULT_PAGE_LIMIT);
        assert_eq!(page_limit(Some(0)), 1);
        assert_eq!(page_limit(Some(10_000)), MAXIMUM_PAGE_LIMIT);
    }

    #[test]
    fn problem_receipts_carry_the_pinned_problem_without_a_trace() {
        let receipt = problem_receipt(ProblemCode::CapacityExhausted);
        let problem = &receipt["problem"];
        assert_eq!(problem["code"], "capacity.exhausted");
        assert_eq!(problem["status"], 409);
        assert!(problem.get("traceId").is_none());
    }

    #[test]
    fn commit_errors_project_to_their_public_codes() {
        assert_eq!(
            problem_of(&CommitError::HoldCeiling),
            ProblemCode::CapacityExhausted
        );
        assert_eq!(
            problem_of(&CommitError::Unauthorized),
            ProblemCode::OperationNotAuthorized
        );
        assert_eq!(
            problem_of(&CommitError::CutoffPassed),
            ProblemCode::CancellationCutoffPassed
        );
        assert_eq!(
            problem_of(&CommitError::KeyReused),
            ProblemCode::IdempotencyKeyReused
        );
    }

    #[test]
    fn the_detailed_code_stays_behind_the_explain_path() {
        let refusal = registry_scheduling_core::AdmissionRefusal::ResourceUnavailable;
        assert_eq!(refusal.public_code(), ProblemCode::CapacityExhausted);
        assert_eq!(refusal.detailed_code(), ProblemCode::ResourceUnavailable);
        // Every other refusal discloses nothing extra.
        assert_eq!(
            registry_scheduling_core::AdmissionRefusal::CapacityExhausted.detailed_code(),
            registry_scheduling_core::AdmissionRefusal::CapacityExhausted.public_code()
        );
    }

    #[test]
    fn a_replayed_receipt_records_the_decision_it_carries() {
        assert_eq!(
            replayed_decision(201, &json!({"claim": {}})),
            (AuthorizationOutcome::Allowed, "authorization.allowed")
        );
        assert_eq!(
            replayed_decision(204, &Value::Null),
            (AuthorizationOutcome::Allowed, "authorization.allowed")
        );
        assert_eq!(
            replayed_decision(403, &problem_receipt(ProblemCode::OperationNotAuthorized)),
            (AuthorizationOutcome::Denied, "authorization.refused")
        );
        for refusal in [
            ProblemCode::CapacityExhausted,
            ProblemCode::RevisionMismatch,
            ProblemCode::CancellationCutoffPassed,
        ] {
            assert_eq!(
                replayed_decision(refusal.http_status(), &problem_receipt(refusal)),
                (AuthorizationOutcome::Denied, "authorization.profile")
            );
        }
    }

    #[test]
    fn a_success_replay_receipt_projects_through_the_same_document() {
        let claim = ClaimRow {
            claim_id: Uuid::new_v4(),
            kind: LedgerKind::Booking,
            state: crate::store::ClaimState::Active,
            offering: "registry-update-30".to_owned(),
            supply_id: "station-1".to_owned(),
            channel: None,
            displayed_start: at(2, 0),
            displayed_end: at(2, 30),
            occupied_start: at(1, 55),
            occupied_end: at(2, 35),
            units: 1,
            allocations: Vec::new(),
            party: None,
            party_references: Vec::new(),
            source_manager: None,
            duplicate_key: None,
            external_references: Vec::new(),
            hold_expires_at: None,
            revision: 1,
            policy_revision: 4,
            actor: "actor-pseudonym".to_owned(),
            reason: None,
            created_at: at(0, 0),
            closed_at: None,
            owner: None,
        };
        // A receipt is the serialized claim, and the verified owner is never
        // part of it: the claim written with an owner and the one read back
        // without serialize identically.
        let owned = ClaimRow {
            owner: Some(crate::store::ClaimOwner {
                issuer: "https://issuer.test".to_owned(),
                subject: "subject-owner".to_owned(),
            }),
            ..claim.clone()
        };
        assert_eq!(
            serde_json::to_value(&owned).expect("a serialized claim"),
            serde_json::to_value(&claim).expect("a serialized claim"),
        );
        assert!(owned.is_owned_by("https://issuer.test", "subject-owner"));
        assert!(!owned.is_owned_by("https://issuer.test", "subject-other"));
        assert!(!owned.is_owned_by("https://other.test", "subject-owner"));
        assert!(!claim.is_owned_by("https://issuer.test", "subject-owner"));
        let mut receipt = json!({
            "kind": "booking",
            "claim": claim.clone(),
            "resource": "station-1",
            "policyRevision": 4
        });
        receipt["claim"]
            .as_object_mut()
            .expect("a claim receipt object")
            .remove("externalReferences");
        let answer: CommitmentAnswer<ClaimRow> = CommitmentAnswer::Replay {
            status_code: 201,
            receipt,
        };
        let replayed = claim_or_replay(answer, |replayed, receipt| {
            (
                replayed.clone(),
                receipt
                    .and_then(|value| value["resource"].as_str())
                    .map(str::to_owned),
            )
        });
        match replayed {
            CommitmentAnswer::Minted((replayed, resource)) => {
                assert_eq!(replayed, claim);
                assert_eq!(resource.as_deref(), Some("station-1"));
            }
            CommitmentAnswer::Replay { .. } => panic!("a claim receipt is a minted answer"),
        }

        let current_policy: SchedulingPolicy = serde_json::from_value(json!({
            "apiVersion": "id.registrystack.org/formats/scheduling/project/v1alpha1",
            "kind": "SchedulingProject",
            "project": {"id": "test", "version": "99"},
            "services": [],
            "offerings": [],
            "holidaySets": [],
            "openings": [],
            "channels": ["public"],
            "holdPolicy": {"ttlMinutes": 5, "maximumPerCaller": 1, "because": "test"}
        }))
        .expect("a policy used only for replay projection");
        let replay_receipt = json!({
            "kind": "booking",
            "claim": claim.clone(),
            "resource": "station-1",
            "policyRevision": 4
        });
        let document = appointment_document(&claim, &current_policy, 99, Some(&replay_receipt));
        assert_eq!(document.resource.as_deref(), Some("station-1"));
        assert_eq!(document.policy_revision, 4);

        let refused: CommitmentAnswer<ClaimRow> = CommitmentAnswer::Replay {
            status_code: 409,
            receipt: problem_receipt(ProblemCode::CapacityExhausted),
        };
        assert!(matches!(
            claim_or_replay(refused, |claim, _| claim.clone()),
            CommitmentAnswer::Replay {
                status_code: 409,
                ..
            }
        ));
    }

    const STATUS_GRANT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const STATUS_SOURCE: &str = "https://authority.test";
    const STATUS_RESOURCE: &str = "urn:registry-scheduling:test";

    fn unix_now() -> u64 {
        u64::try_from(Utc::now().timestamp()).expect("a representable clock")
    }

    fn status_bounds() -> Value {
        json!({"type": "scheduling", "permissions": [{
            "service": "registry-update",
            "location": "north-counter",
            "actions": ["appointment.create"],
        }]})
    }

    /// One task grant as authentication hands it to the service, read at
    /// `read_at` so a test can decide it at a later instant.
    fn verified_grant(source_issuer: &str, expires_at: u64, read_at: u64) -> GrantClaims {
        let claims: registry_platform_oidc::Claims = serde_json::from_value(json!({
            "sub": "principal-agent",
            "exp": expires_at,
            "registry_actor_kind": "agent",
            "registry_purpose": "registry-update",
            "registry_grant_id": STATUS_GRANT_ID,
            "registry_grant_source_issuer": source_issuer,
            "registry_grant_client": "task-agent",
            "registry_grant_resource": STATUS_RESOURCE,
            "registry_grant_exp": expires_at,
            "registry_grant_bounds": status_bounds(),
            "registry_approver": "approver-1",
        }))
        .expect("the grant claims");
        registry_platform_oidc::grant_claims(
            &claims,
            &registry_platform_oidc::ClaimNames::default(),
            read_at,
        )
        .expect("a complete grant")
        .expect("a grant is present")
    }

    fn status_subjects() -> std::collections::BTreeMap<String, Value> {
        std::collections::BTreeMap::from([(
            "subject_reference".to_owned(),
            json!("synthetic-subject"),
        )])
    }

    fn active_answer(grant: &GrantClaims) -> Value {
        json!({"active": true, "grant": {
            "grantId": STATUS_GRANT_ID,
            "sourceIssuer": STATUS_SOURCE,
            "principal": "principal-agent",
            "client": "task-agent",
            "resource": STATUS_RESOURCE,
            "purpose": "registry-update",
            "bounds": status_bounds(),
            "subjects": {"subject_reference": "synthetic-subject"},
            "expiresAt": grant.exp(),
        }})
    }

    /// A status registry that lists only `STATUS_SOURCE`, backed by a mock
    /// authority that issues a service credential and answers every status
    /// call with `response`.
    async fn listed_authority(
        response: wiremock::ResponseTemplate,
    ) -> (wiremock::MockServer, TaskGrantStatusRegistry) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "synthetic-status-service",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "casework:grants:status"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/task-grants/{STATUS_GRANT_ID}/status")))
            .respond_with(response)
            .mount(&server)
            .await;

        let secret_name =
            format!("SCHEDULING_VERDICT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
        let mut key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
        )
        .expect("generate the status client key");
        key.alg = Some("RS256".into());
        let mut private = serde_json::to_value(&key).expect("serialize the status client key");
        for (name, value) in [
            ("d", &key.d),
            ("p", &key.p),
            ("q", &key.q),
            ("dp", &key.dp),
            ("dq", &key.dq),
            ("qi", &key.qi),
        ] {
            if let Some(value) = value {
                private[name] = Value::String(value.clone());
            }
        }
        std::env::set_var(
            &secret_name,
            serde_json::to_string(&private).expect("encode the status client key"),
        );
        let secrets = registry_platform_config::SecretResolver::new(
            [registry_platform_config::SecretProvider::Environment],
            "",
        )
        .expect("the status client secret resolver");
        let base = server.uri();
        let status: crate::config::TaskGrantStatusConfig = serde_json::from_value(json!({
            "sourceIssuer": STATUS_SOURCE,
            "baseUrl": base,
            "tokenEndpoint": format!("{base}/token"),
            "clientAssertionAudience": base,
            "clientId": "scheduling-status",
            "privateKeyRef": format!("secret:env/{secret_name}"),
            "statusResource": "urn:casework:test"
        }))
        .expect("the status authority configuration");
        let registry = TaskGrantStatusRegistry::activate(
            &crate::config::task_grant_status_endpoints(&[status]),
            STATUS_RESOURCE,
            &secrets,
        )
        .expect("activate the task-grant status registry");
        (server, registry)
    }

    async fn status_calls(server: &wiremock::MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("recorded authority calls")
            .into_iter()
            .filter(|request| request.url.path().ends_with("/status"))
            .count()
    }

    #[tokio::test]
    async fn the_offline_path_accepts_only_an_unexpired_grant_with_at_most_fifteen_minutes_left() {
        let now = u64::try_from(at(9, 0).timestamp()).expect("a representable instant");
        for (case, expires_at, expected) in [
            ("one second left", now + 1, Ok(())),
            ("exactly fifteen minutes left", now + 900, Ok(())),
            (
                "one second more than fifteen minutes left",
                now + 901,
                Err(TaskGrantError::Refused),
            ),
            ("an hour left", now + 3_600, Err(TaskGrantError::Refused)),
            (
                "expiring at request entry",
                now,
                Err(TaskGrantError::Refused),
            ),
            ("expired", now - 60, Err(TaskGrantError::Refused)),
        ] {
            let grant = verified_grant(STATUS_SOURCE, expires_at, now - 600);
            for subjects in [None, Some(status_subjects())] {
                assert_eq!(
                    task_grant_verdict(None, subjects, &grant, now).await,
                    expected,
                    "{case}"
                );
            }
        }
    }

    #[tokio::test]
    async fn listed_authorities_refuse_an_unlisted_source_and_an_unbound_grant_without_the_offline_path(
    ) {
        let now = unix_now();
        let (server, registry) = listed_authority(
            wiremock::ResponseTemplate::new(200).set_body_json(json!({"active": false})),
        )
        .await;
        // Ten minutes left would pass the offline path; a listed registry
        // never offers it.
        let unlisted = verified_grant("https://other-authority.test", now + 600, now);
        assert_eq!(
            task_grant_verdict(Some(&registry), Some(status_subjects()), &unlisted, now).await,
            Err(TaskGrantError::Refused),
            "an unlisted source is refused"
        );
        let unbound = verified_grant(STATUS_SOURCE, now + 600, now);
        assert_eq!(
            task_grant_verdict(Some(&registry), None, &unbound, now).await,
            Err(TaskGrantError::Refused),
            "a grant without signed subjects is refused"
        );
        assert_eq!(
            status_calls(&server).await,
            0,
            "no refusal above reaches the authority"
        );
    }

    #[tokio::test]
    async fn fixed_bounds_with_empty_disclosure_still_need_active_exact_status() {
        let now = unix_now();
        let grant = verified_grant(STATUS_SOURCE, now + 3_600, now);
        let mut active = active_answer(&grant);
        active["grant"]["subjects"] = json!({});
        for (response, expected) in [
            (active, Ok(())),
            (active_answer(&grant), Err(TaskGrantError::Refused)),
            (json!({"active":false}), Err(TaskGrantError::Refused)),
        ] {
            let (server, registry) =
                listed_authority(wiremock::ResponseTemplate::new(200).set_body_json(response))
                    .await;
            assert_eq!(
                task_grant_verdict(Some(&registry), Some(Default::default()), &grant, now).await,
                expected
            );
            assert_eq!(
                status_calls(&server).await,
                1,
                "one fresh status observation precedes commitment"
            );
        }
    }

    #[tokio::test]
    async fn a_listed_authority_answer_decides_the_grant() {
        let now = unix_now();
        // An hour left: the listed path is not bounded to fifteen minutes.
        let grant = verified_grant(STATUS_SOURCE, now + 3_600, now);
        for (case, response, expected) in [
            (
                "active",
                wiremock::ResponseTemplate::new(200).set_body_json(active_answer(&grant)),
                Ok(()),
            ),
            (
                "inactive",
                wiremock::ResponseTemplate::new(200).set_body_json(json!({"active": false})),
                Err(TaskGrantError::Refused),
            ),
            (
                "unavailable",
                wiremock::ResponseTemplate::new(503),
                Err(TaskGrantError::Unavailable),
            ),
        ] {
            let (server, registry) = listed_authority(response).await;
            assert_eq!(
                task_grant_verdict(Some(&registry), Some(status_subjects()), &grant, now).await,
                expected,
                "{case}"
            );
            assert_eq!(
                status_calls(&server).await,
                1,
                "{case}: one fresh status call"
            );
        }
    }
}
