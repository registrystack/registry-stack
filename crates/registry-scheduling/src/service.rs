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
//! commitment's audit record is built here with pseudonymized principal,
//! client, grant, and approver references, and refused commitments record
//! their receipt so a replayed idempotency key answers as it first did.

use chrono::{DateTime, TimeDelta, Utc};
use registry_platform_audit::{AuditKeyHasher, AuthorizationAuditEvent, AuthorizationOutcome};
use registry_platform_calendar::CalendarInterval;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_oidc::GrantClaims;
use registry_scheduling_core::{
    admission_request_hash, evaluate_exact_time_admission, evaluate_window_admission,
    location_closure_intervals, location_open_intervals, type_uri, AdmissionRequest,
    AppointmentDocument, AppointmentHistoryEntryDocument, AppointmentStateDocument,
    AvailabilityEntry, CancelAppointmentRequest, Channel, CreateAppointmentRequest,
    ExactTimeContext, ExactTimeOffering, LedgerKind, LedgerSnapshot, OfferingDocument,
    OfferingPolicy, PageDocument, PoolMember, ProblemCode, PublishedWindow, ReminderDocument,
    RescheduleAppointmentRequest, ResourceDocument, SchedulingFacts, SchedulingMode,
    SchedulingModeDocument, SchedulingPolicy, SchedulingServiceDocument, ServiceDocument,
    WindowContext, WindowDocument,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cursors::{
    bind_stored, cursor_expiry, decode_cursor, encode_cursor, CursorError, ListingPosition,
    StoredCursor,
};
use crate::hooks::ActivatedHooks;
use crate::store::{
    ClaimRow, CommitError, CommitOutcome, Commitment, PostgresStore, StoreError, SupplyContext,
};

/// The closed action vocabulary a task grant's scheduling permissions carry.
/// A permission names a service, a location, and the actions it allows there;
/// these are the actions the runtime knows.
pub const HOLD_CREATE_ACTION: &str = "hold.create";
pub const HOLD_RELEASE_ACTION: &str = "hold.release";
pub const APPOINTMENT_CREATE_ACTION: &str = "appointment.create";
pub const APPOINTMENT_RESCHEDULE_ACTION: &str = "appointment.reschedule";
pub const APPOINTMENT_CANCEL_ACTION: &str = "appointment.cancel";

/// The default and maximum page sizes for every listing.
pub const DEFAULT_PAGE_LIMIT: usize = 50;
pub const MAXIMUM_PAGE_LIMIT: usize = 200;

/// How far one availability search may span. A search is bounded (BKG-01);
/// a wider ask is served from the first 62 days and continues by cursor.
const MAXIMUM_AVAILABILITY_SPAN_DAYS: i64 = 62;

/// The audit reference class for a booking caller, hashed over the verified
/// issuer and subject pair. Claims, history, and the idempotency ceiling all
/// key on this pseudonym, never on the raw identity.
const PRINCIPAL_CLASS: &str = "scheduling-principal-v1";

/// The audit reference class for the authority that minted a credential
/// carrying no task grant. It exists only so a refusal decided before any
/// grant was resolved still names an accountable second party; a different
/// class is a different keyed domain, so a digest written under it can never
/// be mistaken for the pseudonym of a client that actually presented a grant.
const ISSUER_CLASS: &str = "scheduling-issuer-v1";

/// One verified caller, as the authenticator resolved them.
pub struct Caller {
    /// The verified actor kind: `human`, `agent`, or `service`.
    pub actor_kind: String,
    /// The verified token issuer and subject. The idempotency attempts key
    /// on this pair; every other record carries the pseudonym.
    pub issuer: String,
    pub subject: String,
    /// The verified task grant, when the token carried one.
    pub grant: Option<GrantClaims>,
}

impl Caller {
    /// The pseudonymized actor reference claims and history carry.
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
    attempt_receipt_days: i64,
    hooks: Option<ActivatedHooks>,
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
        attempt_receipt_days: u16,
    ) -> Self {
        Self {
            store,
            policy,
            scheduling_id,
            policy_revision: u64::try_from(policy_revision).unwrap_or(u64::MAX),
            policy_digest,
            hasher,
            attempt_receipt_days: i64::from(attempt_receipt_days),
            hooks: None,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: ActivatedHooks) -> Self {
        self.hooks = Some(hooks);
        self
    }

    fn revision(&self) -> u64 {
        self.policy_revision
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
        let mut offerings: Vec<_> = self
            .policy
            .offerings
            .iter()
            .map(|offering| self.offering_document(offering))
            .collect();
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
                |(resource_id, pool, capabilities, available)| ResourceDocument {
                    resource_id,
                    pool,
                    capabilities,
                    available,
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
        let limit = page_limit(limit);
        let offering = self.published_offering(offering_id)?;
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
            Some(end) => end.max(from + TimeDelta::minutes(1)).min(from + span),
            None => minted_interval.map(|(_, to)| to).unwrap_or(from + span),
        };
        let context = format!("availability:{offering_id}:{}:{to}", from.to_rfc3339());
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
                exact,
                members,
                open,
                ..
            } => {
                let duration = TimeDelta::minutes(i64::from(exact.duration_minutes));
                let buffer = TimeDelta::minutes(i64::from(
                    exact.buffer_before_minutes + exact.buffer_after_minutes,
                ));
                let ids: Vec<String> = members.iter().map(|m| m.resource_id.clone()).collect();
                // The snapshot window widens by the duration and both buffers:
                // a booking that intrudes on any listed slot's occupied span
                // must be in the snapshot, wherever it starts.
                let snapshot = self
                    .store
                    .member_snapshot(&ids, from - buffer, to + duration + buffer, now)
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
                window,
                lead_time_minutes,
                horizon_days,
                ..
            } => {
                let snapshot = self.store.window_snapshot(&window.id, now).await?;
                window_entries(
                    &window,
                    &snapshot,
                    from,
                    to,
                    now,
                    lead_time_minutes,
                    horizon_days,
                )
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
    /// party, so the codes explain the calendar and the capacity, never
    /// another caller's booking.
    pub async fn explain(
        &self,
        offering_id: &str,
        start: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<registry_scheduling_core::ExplainDocument, ServiceError> {
        let offering = self.published_offering(offering_id)?;
        let probe = AdmissionRequest {
            offering: offering.id.clone(),
            start,
            party: registry_scheduling_core::PartyCounts {
                recipients: 1,
                attendees: 1,
            },
            channel: None,
            duplicate_key: None,
            policy_revision: self.revision(),
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
        };
        let refusal = match self.supply(offering).await?.0 {
            ResolvedSupply::ExactTime {
                exact,
                members,
                open,
                closures,
            } => {
                let duration = TimeDelta::minutes(i64::from(exact.duration_minutes));
                let buffer = TimeDelta::minutes(i64::from(
                    exact.buffer_before_minutes + exact.buffer_after_minutes,
                ));
                let ids: Vec<String> = members.iter().map(|m| m.resource_id.clone()).collect();
                let snapshot = self
                    .store
                    .member_snapshot(
                        &ids,
                        start - buffer - duration,
                        start + duration + buffer,
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
                window,
                lead_time_minutes,
                horizon_days,
                channels,
            } => {
                // The probe carries the window's current revision, the way a
                // booking request would: window admission checks capacity
                // only under a revision the caller actually observed, and an
                // explain that never names one answers every window with a
                // revision mismatch instead of explaining the start.
                let mut probe = probe.clone();
                probe.window_revision = Some(window.revision);
                let snapshot = self.store.window_snapshot(&window.id, now).await?;
                evaluate_window_admission(
                    &WindowContext {
                        offering,
                        window: &window,
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

    /// Reserve an admission instead of committing it.
    pub async fn create_hold(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        request: &AdmissionRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<registry_scheduling_core::HoldDocument>, ServiceError> {
        let offering = self.published_offering(&request.offering)?;
        let grant = self
            .require_permission(caller, offering, HOLD_CREATE_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self.supply(offering).await?;
        let request_hash = admission_request_hash(request);
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            HOLD_CREATE_ACTION,
            now,
            facts_revision,
        )?;
        let outcome = self
            .store
            .create_hold(
                offering,
                &supply.context(),
                request,
                self.policy.hold_policy.ttl_minutes,
                self.policy.hold_policy.max_per_caller,
                commitment,
            )
            .await;
        let answer = self
            .commitment_outcome(
                outcome,
                caller,
                &grant,
                &actor,
                idempotency_key,
                &request_hash,
                "hold:create",
                HOLD_CREATE_ACTION,
                now,
                facts_revision,
            )
            .await?;
        Ok(claim_or_replay(answer, |claim| {
            hold_document(claim, &self.policy, self.revision())
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
            .store
            .claim(hold_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::HoldReleased))?;
        if hold.kind != LedgerKind::Hold {
            return Err(ServiceError::Problem(ProblemCode::HoldReleased));
        }
        let offering = self.policy.offering(&hold.offering).ok_or_else(|| {
            ServiceError::internal("a committed hold names no offering in the policy")
        })?;
        let grant = self
            .require_permission(caller, offering, HOLD_RELEASE_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let request_hash = canonical_hash(&json!({"hold": hold_id}))?;
        // The release carries no caller-chosen key, so the hold's own id is
        // the idempotency key: a retried release replays the first answer.
        let release_key = hold_id.to_string();
        // A release evaluates no supply, so no records revision guards it:
        // closing a hold cannot name a resource.
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            &release_key,
            &request_hash,
            HOLD_RELEASE_ACTION,
            now,
            0,
        )?;
        let outcome = self.store.release_hold(hold_id, commitment).await;
        self.commitment_outcome(
            outcome,
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
        Ok(claim_or_replay(answer, |claim| {
            appointment_document(claim, &self.policy, self.revision())
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
            .store
            .claim(hold_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::HoldReleased))?;
        if hold.kind != LedgerKind::Hold {
            return Err(ServiceError::Problem(ProblemCode::HoldReleased));
        }
        let offering = self.policy.offering(&hold.offering).ok_or_else(|| {
            ServiceError::internal("a committed hold names no offering in the policy")
        })?;
        let grant = self
            .require_permission(caller, offering, APPOINTMENT_CREATE_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self.supply(offering).await?;
        let request_hash = canonical_hash(&json!({"hold": hold_id}))?;
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            APPOINTMENT_CREATE_ACTION,
            now,
            facts_revision,
        )?;
        let outcome = self
            .store
            .confirm_hold(hold_id, offering, &supply.context(), commitment)
            .await;
        self.commitment_outcome(
            outcome,
            caller,
            &grant,
            &actor,
            idempotency_key,
            &request_hash,
            &format!("hold:{hold_id}:confirm"),
            APPOINTMENT_CREATE_ACTION,
            now,
            facts_revision,
        )
        .await
    }

    async fn direct_create_appointment(
        &self,
        caller: &Caller,
        idempotency_key: &str,
        request: &AdmissionRequest,
        now: DateTime<Utc>,
    ) -> Result<CommitmentAnswer<ClaimRow>, ServiceError> {
        let offering = self.published_offering(&request.offering)?;
        let grant = self
            .require_permission(caller, offering, APPOINTMENT_CREATE_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self.supply(offering).await?;
        let request_hash = admission_request_hash(request);
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            APPOINTMENT_CREATE_ACTION,
            now,
            facts_revision,
        )?;
        let outcome = self
            .store
            .create_appointment(offering, &supply.context(), request, commitment)
            .await;
        self.commitment_outcome(
            outcome,
            caller,
            &grant,
            &actor,
            idempotency_key,
            &request_hash,
            "appointment:create",
            APPOINTMENT_CREATE_ACTION,
            now,
            facts_revision,
        )
        .await
    }

    /// One appointment by id, visible to the caller that owns it.
    pub async fn get_appointment(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
    ) -> Result<AppointmentDocument, ServiceError> {
        let claim = self
            .owned_booking(caller, appointment_id)
            .await?
            .ok_or(ServiceError::Problem(ProblemCode::OperationNotAuthorized))?;
        Ok(appointment_document(&claim, &self.policy, self.revision()))
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
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let (supply, facts_revision) = self.supply(offering).await?;
        let request_hash = canonical_hash(&json!({
            "observedRevision": request.observed_revision,
            "admissionHash": admission_request_hash(&request.admission),
        }))?;
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            APPOINTMENT_RESCHEDULE_ACTION,
            now,
            facts_revision,
        )?;
        let outcome = self
            .store
            .reschedule_appointment(
                appointment_id,
                offering,
                &supply.context(),
                &request.admission,
                request.observed_revision,
                commitment,
            )
            .await;
        let answer = self
            .commitment_outcome(
                outcome,
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
        Ok(claim_or_replay(answer, |claim| {
            appointment_document(claim, &self.policy, self.revision())
        }))
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
        let offering = self.policy.offering(&appointment.offering).ok_or_else(|| {
            ServiceError::internal("a committed appointment names no offering in the policy")
        })?;
        let grant = self
            .require_permission(caller, offering, APPOINTMENT_CANCEL_ACTION)
            .await?;
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        let request_hash = canonical_hash(&json!({
            "observedRevision": request.observed_revision,
            "reason": request.reason,
        }))?;
        // A cancellation evaluates no supply, so no records revision guards
        // it: closing an appointment cannot name a resource.
        let commitment = self.commitment(
            caller,
            &actor,
            &grant,
            idempotency_key,
            &request_hash,
            APPOINTMENT_CANCEL_ACTION,
            now,
            0,
        )?;
        let outcome = self
            .store
            .cancel_appointment(
                appointment_id,
                request.observed_revision,
                Some(offering.cancellation_cutoff_minutes),
                request.reason.as_deref(),
                commitment,
            )
            .await;
        let answer = self
            .commitment_outcome(
                outcome,
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
        Ok(claim_or_replay(answer, |claim| {
            appointment_document(claim, &self.policy, self.revision())
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

    /// `booking`, and the caller owns it.
    async fn owned_booking(
        &self,
        caller: &Caller,
        appointment_id: Uuid,
    ) -> Result<Option<ClaimRow>, ServiceError> {
        let Some(claim) = self.booking(appointment_id).await? else {
            return Ok(None);
        };
        let actor = caller.actor_pseudonym(&self.hasher, &self.scheduling_id)?;
        if claim.actor != actor {
            return Ok(None);
        }
        Ok(Some(claim))
    }

    fn offering_document(&self, offering: &OfferingPolicy) -> OfferingDocument {
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
                    Some(exact.max_recipients),
                ),
                None => (None, None, None, None, None),
            };
        let window = offering.arrival.as_ref().map(|arrival| {
            let window = self
                .policy
                .window(&arrival.window)
                .expect("a published offering names a declared window");
            WindowDocument {
                id: window.id.clone(),
                revision: window.revision,
                start: window.start,
                end: window.end,
                units: window.units,
            }
        });
        let (lead_time_minutes, horizon_days) = match (&offering.exact_time, &offering.arrival) {
            (Some(exact), None) => (exact.lead_time_minutes, exact.horizon_days),
            (None, Some(arrival)) => (arrival.lead_time_minutes, arrival.horizon_days),
            _ => (0, 0),
        };
        OfferingDocument {
            id: offering.id.clone(),
            service: offering.service.clone(),
            label: offering.label.clone(),
            mode,
            location: offering.location.clone(),
            lead_time_minutes,
            horizon_days,
            cancellation_cutoff_minutes: offering.cancellation_cutoff_minutes,
            duration_minutes: duration,
            buffer_before_minutes: buffer_before,
            buffer_after_minutes: buffer_after,
            start_increment_minutes: increment,
            max_recipients,
            window,
            reminders: offering
                .reminders
                .iter()
                .map(|reminder| ReminderDocument {
                    minutes_before: reminder.minutes_before,
                })
                .collect(),
            requires_capabilities: offering.requires_capabilities.clone(),
            prerequisites: offering.prerequisites.clone(),
        }
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
    /// Both refusals are audited. A refusal decided here never opens the
    /// capacity transaction, so nothing further in the request would record
    /// that it happened, and a caller probing which services and locations its
    /// grant reaches would leave the journal empty. What the journal gains is
    /// the attribution: the answer stays the same closed code, naming neither
    /// the bound that failed nor whether a grant was carried at all.
    async fn require_permission(
        &self,
        caller: &Caller,
        offering: &OfferingPolicy,
        action: &str,
    ) -> Result<GrantClaims, ServiceError> {
        let Some(grant) = &caller.grant else {
            self.record_refusal(grantless_refusal_record(
                &self.hasher,
                &self.scheduling_id,
                caller,
                action,
            ))
            .await;
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
            self.record_refusal(audit_record(
                &self.hasher,
                &self.scheduling_id,
                caller,
                grant,
                action,
                AuthorizationOutcome::Denied,
                "authorization.refused",
            ))
            .await;
            Err(ServiceError::Problem(ProblemCode::OperationNotAuthorized))
        }
    }

    /// Write one authorization refusal to the journal. A journal that cannot
    /// be written must not change the caller's answer: the decision is already
    /// made and the caller is refused either way, so the failure is logged
    /// loudly and the refusal stands.
    async fn record_refusal(&self, record: Result<Value, ServiceError>) {
        match record {
            Ok(record) => {
                if let Err(failure) = self
                    .store
                    .record_refusal_audit(Uuid::new_v4(), record)
                    .await
                {
                    tracing::error!(%failure, "the refusal audit row could not be recorded");
                }
            }
            Err(refused) => {
                tracing::error!(error = %refused, "the refusal audit row could not be built");
            }
        }
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

    #[allow(clippy::too_many_arguments)]
    fn commitment<'a>(
        &'a self,
        caller: &'a Caller,
        actor: &'a str,
        grant: &GrantClaims,
        idempotency_key: &'a str,
        request_hash: &'a str,
        operation: &str,
        now: DateTime<Utc>,
        facts_revision: i64,
    ) -> Result<Commitment<'a>, ServiceError> {
        let attempt_expires_at = now
            .checked_add_signed(TimeDelta::days(self.attempt_receipt_days))
            .ok_or_else(|| {
                ServiceError::internal("the attempt retention horizon is not representable")
            })?;
        let audit_record = audit_record(
            &self.hasher,
            &self.scheduling_id,
            caller,
            grant,
            operation,
            AuthorizationOutcome::Allowed,
            "authorization.allowed",
        )?;
        Ok(Commitment {
            now,
            policy_revision: i64::try_from(self.policy_revision).unwrap_or(i64::MAX),
            facts_revision,
            actor,
            actor_issuer: &caller.issuer,
            actor_subject: &caller.subject,
            idempotency_key,
            request_hash,
            attempt_expires_at,
            grant_exp_unix: Some(grant.exp()),
            audit_event: Uuid::new_v4(),
            audit_record,
            hooks: self.hooks.as_ref(),
        })
    }

    /// Translate one store outcome: minted, replayed, or refused. A refusal
    /// writes its receipt under the caller's idempotency key so a replay of
    /// that key answers the same, and writes its audit row when the refusal
    /// was an authorization decision.
    #[allow(clippy::too_many_arguments)]
    async fn commitment_outcome<T>(
        &self,
        outcome: Result<CommitOutcome, CommitError>,
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
            }) => Ok(CommitmentAnswer::Replay {
                status_code,
                receipt,
            }),
            Ok(minted) => Ok(CommitmentAnswer::Minted(T::from_minted(minted))),
            Err(error) => {
                if matches!(
                    error,
                    CommitError::Store(_) | CommitError::Query(_) | CommitError::Hooks(_)
                ) {
                    // Nothing was decided: no receipt, no audit row, and the
                    // caller sees no detail.
                    tracing::error!(%error, "the Scheduling store failed mid-commitment");
                    return Err(ServiceError::Problem(ProblemCode::ServiceUnavailable));
                }
                if matches!(error, CommitError::FactsStale) {
                    // A records replacement moved under this request. Nothing
                    // was decided and the caller retries; the swap is an
                    // expected operator act, so this is a warning, not a
                    // failure.
                    tracing::warn!(
                        %error,
                        "the environment records were replaced while a commitment was in flight"
                    );
                    return Err(ServiceError::Problem(ProblemCode::ServiceUnavailable));
                }
                let problem = problem_of(&error);
                // Key misuse keeps the stored attempt as the answer and
                // records nothing new.
                if !matches!(error, CommitError::KeyReused | CommitError::KeyExpired) {
                    let receipt = self.commitment(
                        caller,
                        actor,
                        grant,
                        idempotency_key,
                        request_hash,
                        operation,
                        now,
                        facts_revision,
                    );
                    match receipt {
                        Ok(commitment) => {
                            if let Err(failure) = self
                                .store
                                .record_refused_attempt(
                                    &commitment,
                                    scope,
                                    problem.http_status(),
                                    problem_receipt(problem),
                                )
                                .await
                            {
                                tracing::error!(%failure, "the refused attempt receipt could not be recorded");
                            }
                        }
                        Err(refused) => {
                            tracing::error!(error = %refused, "the refused attempt could not be recorded");
                        }
                    }
                }
                if matches!(
                    error,
                    CommitError::Refused(_) | CommitError::HoldCeiling | CommitError::Unauthorized
                ) {
                    let reason = match error {
                        CommitError::Unauthorized => "authorization.refused",
                        _ => "authorization.profile",
                    };
                    self.record_refusal(audit_record(
                        &self.hasher,
                        &self.scheduling_id,
                        caller,
                        grant,
                        operation,
                        AuthorizationOutcome::Denied,
                        reason,
                    ))
                    .await;
                }
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

/// The minted-claim projection each commitment answer carries.
pub trait FromMinted {
    fn from_minted(outcome: CommitOutcome) -> Self;
}

impl FromMinted for ClaimRow {
    fn from_minted(outcome: CommitOutcome) -> Self {
        match outcome {
            CommitOutcome::Booking(claim) | CommitOutcome::Hold(claim) => claim,
            CommitOutcome::Cancelled(claim) => claim,
            CommitOutcome::Released => unreachable!("a release is not a minted claim"),
            CommitOutcome::Replay { .. } => unreachable!("a replay is not a minted claim"),
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
    project: impl FnOnce(&ClaimRow) -> T,
) -> CommitmentAnswer<T> {
    match answer {
        CommitmentAnswer::Minted(claim) => CommitmentAnswer::Minted(project(&claim)),
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => {
            if let Some(claim) = receipt
                .get("claim")
                .cloned()
                .and_then(|value| serde_json::from_value::<ClaimRow>(value).ok())
            {
                CommitmentAnswer::Minted(project(&claim))
            } else {
                CommitmentAnswer::Replay {
                    status_code,
                    receipt,
                }
            }
        }
    }
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
        window: PublishedWindow,
        lead_time_minutes: u32,
        horizon_days: u32,
        channels: Vec<Channel>,
    },
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
                let window = policy
                    .window(&arrival.window)
                    .ok_or_else(|| operator_gap(&arrival.window))?;
                Ok(Self::Window {
                    window: window.clone(),
                    lead_time_minutes: arrival.lead_time_minutes,
                    horizon_days: arrival.horizon_days,
                    channels: policy.channels.clone(),
                })
            }
            _ => Err(operator_gap("one scheduling mode")),
        }
    }

    fn context(&self) -> SupplyContext<'_> {
        match self {
            Self::ExactTime {
                exact,
                members,
                open,
                closures,
            } => SupplyContext::ExactTime {
                exact,
                members,
                open,
                closures,
            },
            Self::Window {
                window,
                lead_time_minutes,
                horizon_days,
                channels,
            } => SupplyContext::Window {
                window,
                lead_time_minutes: *lead_time_minutes,
                horizon_days: *horizon_days,
                channels: channels.as_slice(),
            },
        }
    }
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
    let earliest = now + TimeDelta::minutes(i64::from(exact.lead_time_minutes));
    let latest = now + TimeDelta::days(i64::from(exact.horizon_days));
    let mut entries = Vec::new();
    for interval in open {
        // Slots anchor on each published opening's own start and step the
        // authored grid; a start that leaves the opening is not offered.
        let mut slot_start = interval.start;
        while slot_start + duration <= interval.end {
            let slot_end = slot_start + duration;
            let occupied_start =
                slot_start - TimeDelta::minutes(i64::from(exact.buffer_before_minutes));
            let occupied_end = slot_end + TimeDelta::minutes(i64::from(exact.buffer_after_minutes));
            let in_range = slot_start >= from && slot_start < to;
            let in_horizon = slot_start >= earliest && slot_start <= latest;
            if in_range && in_horizon {
                let free = members
                    .iter()
                    .filter(|member| member.available)
                    .filter(|member| member.serves(requires_capabilities))
                    .filter(|member| {
                        snapshot.claims.iter().all(|claim| {
                            claim.supply_id != member.resource_id
                                || claim.end <= occupied_start
                                || occupied_end <= claim.start
                        })
                    })
                    .count();
                if free > 0 {
                    entries.push(AvailabilityEntry::Slot {
                        start: slot_start,
                        end: slot_end,
                        free: u32::try_from(free).unwrap_or(u32::MAX),
                    });
                }
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
fn window_entries(
    window: &PublishedWindow,
    snapshot: &LedgerSnapshot,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
    lead_time_minutes: u32,
    horizon_days: u32,
) -> Vec<AvailabilityEntry> {
    let consumed: u32 = snapshot.claims.iter().map(|claim| claim.units).sum();
    let remaining = window.units.saturating_sub(consumed);
    let earliest = now + TimeDelta::minutes(i64::from(lead_time_minutes));
    let latest = now + TimeDelta::days(i64::from(horizon_days));
    let in_range = window.start >= from && window.start < to;
    let in_horizon = window.start >= earliest && window.start <= latest;
    if in_range && in_horizon && remaining > 0 {
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
) -> registry_scheduling_core::HoldDocument {
    registry_scheduling_core::HoldDocument {
        hold_id: claim.claim_id.to_string(),
        offering: claim.offering.clone(),
        start: claim.displayed_start,
        end: claim.displayed_end,
        resource: claim
            .supply_id_is_member(policy)
            .then(|| claim.supply_id.clone()),
        units: u32::try_from(claim.units).unwrap_or(u32::MAX),
        expires_at: claim.hold_expires_at.unwrap_or(claim.created_at),
        policy_revision,
    }
}

fn appointment_document(
    claim: &ClaimRow,
    policy: &SchedulingPolicy,
    policy_revision: u64,
) -> AppointmentDocument {
    AppointmentDocument {
        appointment_id: claim.claim_id.to_string(),
        offering: claim.offering.clone(),
        start: claim.displayed_start,
        end: claim.displayed_end,
        resource: claim
            .supply_id_is_member(policy)
            .then(|| claim.supply_id.clone()),
        units: u32::try_from(claim.units).unwrap_or(u32::MAX),
        channel: claim.channel.clone(),
        revision: u64::try_from(claim.revision).unwrap_or(u64::MAX),
        state: if claim.state == crate::store::ClaimState::Cancelled {
            AppointmentStateDocument::Cancelled
        } else {
            AppointmentStateDocument::Confirmed
        },
        policy_revision,
        created_at: claim.created_at,
        cancelled_at: claim.closed_at,
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
        CommitError::CutoffPassed => ProblemCode::CancellationCutoffPassed,
        // Never reached: the outcome handler intercepts a stale-facts
        // refusal before it projects, because nothing was decided.
        CommitError::FactsStale => ProblemCode::ServiceUnavailable,
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
/// reader of the journal which of the two it is looking at.
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

    fn interval(start_hour: u32, end_hour: u32) -> CalendarInterval {
        let day = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
        CalendarInterval {
            start: day + TimeDelta::hours(i64::from(start_hour)),
            end: day + TimeDelta::hours(i64::from(end_hour)),
        }
    }

    fn exact() -> ExactTimeOffering {
        ExactTimeOffering {
            duration_minutes: 30,
            buffer_before_minutes: 5,
            buffer_after_minutes: 5,
            lead_time_minutes: 60,
            horizon_days: 30,
            pool: "north-stations".to_owned(),
            start_increment_minutes: 30,
            max_recipients: 2,
        }
    }

    fn members(count: usize) -> Vec<PoolMember> {
        (1..=count)
            .map(|index| PoolMember {
                resource_id: format!("station-{index}"),
                capabilities: Vec::new(),
                available: true,
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
            duplicate_key: None,
            hold_expires_at: None,
            revision: 1,
            policy_revision: 4,
            actor: "actor-pseudonym".to_owned(),
            reason: None,
            created_at: at(0, 0),
            closed_at: None,
        };
        let receipt = json!({"kind": "booking", "claim": claim.clone()});
        let answer: CommitmentAnswer<ClaimRow> = CommitmentAnswer::Replay {
            status_code: 201,
            receipt,
        };
        let replayed = claim_or_replay(answer, |replayed| replayed.clone());
        match replayed {
            CommitmentAnswer::Minted(replayed) => assert_eq!(replayed, claim),
            CommitmentAnswer::Replay { .. } => panic!("a claim receipt is a minted answer"),
        }

        let refused: CommitmentAnswer<ClaimRow> = CommitmentAnswer::Replay {
            status_code: 409,
            receipt: problem_receipt(ProblemCode::CapacityExhausted),
        };
        assert!(matches!(
            claim_or_replay(refused, |claim| claim.clone()),
            CommitmentAnswer::Replay {
                status_code: 409,
                ..
            }
        ));
    }
}
