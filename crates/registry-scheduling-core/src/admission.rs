// SPDX-License-Identifier: Apache-2.0

//! The pure admission evaluators.
//!
//! One admission decision is one function of the resolved policy, the
//! environment facts, the authoritative ledger snapshot, the request, and the
//! observed instant. Nothing here reads a clock, opens a socket, or touches a
//! database: the runtime calls these functions inside its capacity
//! transaction, the explain endpoint calls them again for an authorized
//! caller, and offline fixture replay calls them with synthetic facts. The
//! three callers therefore cannot disagree about what admits.
//!
//! A refusal carries two problem codes: the public one every caller may see,
//! and the detailed one the separately authorized explain path may see. The
//! one place they differ is resource unavailability: the public answer to
//! "why not" is that capacity is exhausted, never which resource was absent
//! or why, because a specific resource's absence can disclose another
//! person's booking or a private staff reason.

use chrono::{DateTime, Duration, Utc};

use registry_platform_calendar::CalendarInterval;

use crate::allocation::{
    allocate_bundle, AllocatedResource, AllocationCandidate, AllocationContext, AllocationError,
    AllocationInterval, AllocationLimits, AllocationRequirement, StandingAllocation,
};
use crate::model::{AdmissionRequest, LedgerClaim, LedgerKind, LedgerSnapshot, PoolMember};
use crate::policy::{
    check_additional_allocation_policy, AdditionalAllocationPolicyError, Channel,
    ExactTimeOffering, OfferingPolicy, OpeningCoverage, PublishedWindow,
};
use crate::problem::ProblemCode;
use crate::units::UnitsEvaluationError;

/// A granted admission and the allocation it would create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    pub offering: String,
    /// The displayed start.
    pub start: DateTime<Utc>,
    /// The displayed end, start plus duration.
    pub end: DateTime<Utc>,
    /// The occupied interval including setup and cleanup buffers, the interval
    /// the ledger records.
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
    /// The concrete pool member chosen for an exact-time admission. Pooled
    /// supply is its members, so the decision names one.
    pub resource: Option<String>,
    /// The recipient units consumed.
    pub units: u32,
}

/// One exact-time line resolved by the service from the same policy and facts
/// revisions as every other line in an atomic bundle.
pub struct ExactTimeBundleLineContext<'a> {
    pub requirement_id: String,
    pub offering: &'a OfferingPolicy,
    pub exact: &'a ExactTimeOffering,
    pub members: &'a [PoolMember],
    pub open: &'a [CalendarInterval],
    pub closures: &'a [CalendarInterval],
    pub resource: Option<&'a str>,
    /// True only when the resource is a stored assignment being confirmed.
    pub stored_resource: bool,
    pub units: u32,
}

/// The complete pure input for exact-time bundle evaluation.
pub struct ExactTimeBundleContext<'a> {
    pub lines: &'a [ExactTimeBundleLineContext<'a>],
    pub snapshot: &'a LedgerSnapshot,
    pub policy_revision: u64,
    pub now: DateTime<Utc>,
    pub exclude_reservation: Option<&'a str>,
    /// True only when confirming a held start. An earlier admission already
    /// accepted that start, so the booking horizon (lead time included) is
    /// not checked again.
    pub confirming_hold: bool,
    pub limits: AllocationLimits,
}

/// One concrete member allocation in an admitted logical bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleAllocation {
    pub requirement_id: String,
    pub offering: String,
    pub resource: String,
    pub units: u32,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
}

/// A granted logical bundle. Every member allocation must be stored or none
/// of them may be stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleAdmission {
    pub offering: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub allocations: Vec<BundleAllocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BundleEvaluationError {
    #[error(transparent)]
    Admission(#[from] AdmissionRefusal),
    #[error(transparent)]
    Policy(#[from] AdditionalAllocationPolicyError),
    #[error(transparent)]
    Allocation(#[from] AllocationError),
    #[error("the resolved bundle lines do not match the request")]
    Shape,
}

/// Which side of the booking horizon the request fell on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HorizonKind {
    /// The start is closer than the offering's lead time allows.
    TooSoon,
    /// The start is further ahead than the offering's horizon allows.
    TooFar,
}

/// A refused admission. The variants are the decision; the codes are the
/// disclosure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmissionRefusal {
    #[error("the policy revision changed before the request committed")]
    PolicyChanged,
    #[error("the window revision changed before the request committed")]
    RevisionMismatch { observed: u64 },
    #[error("the start is outside the booking horizon")]
    HorizonOutside { kind: HorizonKind },
    #[error("no published schedule serves that start")]
    ScheduleUnpublished,
    #[error("a closure covers that start")]
    LocationClosed,
    #[error("the party is larger than the offering can ever serve")]
    PartyCapacityInadequate,
    #[error("the party is missing required prerequisites")]
    PrerequisiteMissing { missing: Vec<String> },
    #[error("the request names a channel the closed vocabulary or the policy does not serve")]
    ChannelUnknown,
    #[error("the party or backing supply lacks a required capability")]
    CapabilityUnmatched,
    #[error("the requested duration is outside the offering's selection policy")]
    DurationOutOfPolicy,
    #[error("the offering does not permit exact resource selection")]
    ResourceSelectionNotAllowed,
    #[error("the selected resource is not a member of the offering's pool")]
    ResourceNotInPool,
    #[error("an active booking already holds this party's duplicate key")]
    DuplicateActiveBooking,
    #[error("the offering keys duplicate actives, so the request must carry a key")]
    DuplicateKeyRequired,
    #[error("every capable member is unavailable")]
    ResourceUnavailable,
    #[error("the supply is fully committed for that interval")]
    CapacityExhausted,
    #[error("the request requires the atomic bundle evaluator")]
    AtomicBundleRequired,
    #[error("the hold expired before confirmation")]
    HoldExpired,
    #[error("the claim is not an active hold")]
    HoldReleased,
}

impl AdmissionRefusal {
    /// The problem code every caller may see.
    #[must_use]
    pub const fn public_code(&self) -> ProblemCode {
        match self {
            Self::ResourceUnavailable { .. } => ProblemCode::CapacityExhausted,
            Self::PolicyChanged { .. } => ProblemCode::PolicyChanged,
            Self::RevisionMismatch { .. } => ProblemCode::RevisionMismatch,
            Self::HorizonOutside { .. } => ProblemCode::HorizonOutside,
            Self::ScheduleUnpublished { .. } => ProblemCode::ScheduleUnpublished,
            Self::LocationClosed { .. } => ProblemCode::LocationClosed,
            Self::PartyCapacityInadequate { .. } => ProblemCode::PartyCapacityInadequate,
            Self::PrerequisiteMissing { .. } => ProblemCode::PrerequisiteMissing,
            Self::ChannelUnknown => ProblemCode::RequestUnprocessable,
            Self::CapabilityUnmatched { .. } => ProblemCode::CapabilityUnmatched,
            Self::DurationOutOfPolicy
            | Self::ResourceSelectionNotAllowed
            | Self::ResourceNotInPool
            | Self::AtomicBundleRequired => ProblemCode::RequestUnprocessable,
            Self::DuplicateActiveBooking { .. } => ProblemCode::BookingDuplicateActive,
            Self::DuplicateKeyRequired { .. } => ProblemCode::PreconditionRequired,
            Self::CapacityExhausted { .. } => ProblemCode::CapacityExhausted,
            Self::HoldExpired { .. } => ProblemCode::HoldExpired,
            Self::HoldReleased { .. } => ProblemCode::HoldReleased,
        }
    }

    /// The problem code only the separately authorized explain path may see.
    #[must_use]
    pub const fn detailed_code(&self) -> ProblemCode {
        match self {
            Self::ResourceUnavailable { .. } => ProblemCode::ResourceUnavailable,
            other => other.public_code(),
        }
    }
}

/// The resolved state an exact-time admission runs against.
pub struct ExactTimeContext<'a> {
    pub offering: &'a OfferingPolicy,
    pub exact: &'a ExactTimeOffering,
    /// The pool's members, as runtime records hold them.
    pub members: &'a [PoolMember],
    /// The expanded published openings for the offering's location.
    pub open: &'a [CalendarInterval],
    /// The blocking closures for the offering's location, so a refused start
    /// can distinguish a closure from no published schedule.
    pub closures: &'a [CalendarInterval],
    pub snapshot: &'a LedgerSnapshot,
    pub policy_revision: u64,
    pub now: DateTime<Utc>,
}

/// The resolved state an arrival-window admission runs against.
pub struct WindowContext<'a> {
    pub offering: &'a OfferingPolicy,
    pub window: &'a PublishedWindow,
    /// Effective published openings for the window's location, after dated
    /// closures and authorized reopenings have been layered.
    pub open: &'a [CalendarInterval],
    /// Raw blocking closures, used only to distinguish `location.closed`
    /// from a start outside every published opening.
    pub closures: &'a [CalendarInterval],
    /// The arrival block's lead time and horizon, resolved from the offering.
    pub lead_time_minutes: u32,
    pub horizon_days: u32,
    pub snapshot: &'a LedgerSnapshot,
    pub policy_revision: u64,
    /// The channels the policy declares it serves. The channel vocabulary
    /// itself is closed; the declaration narrows it to the served subset, and
    /// a request naming a channel outside either is refused before any
    /// capacity is counted. An empty slice serves no channel.
    pub channels: &'a [Channel],
    pub now: DateTime<Utc>,
}

/// Evaluate one exact-time admission request.
///
/// The checks run in a fixed order so two callers replaying the same state
/// always see the same first refusal: policy revision, window-agnostic
/// horizon, party bounds, prerequisites, duplicate key, published schedule
/// coverage including the start grid, member capability and availability,
/// then member occupancy including buffers.
///
/// `exclude` is the one standing claim this request replaces: a reschedule
/// must not compete with the appointment it is moving. It is never a value a
/// caller sends. The runtime supplies the appointment's own id from inside
/// the commitment transaction, and offline replay supplies the claim the
/// authored case names, so no create path can name another party's
/// allocation out of the capacity check.
pub fn evaluate_exact_time_admission(
    context: &ExactTimeContext<'_>,
    request: &AdmissionRequest,
    exclude: Option<&str>,
) -> Result<Admission, AdmissionRefusal> {
    if request.resource_units != 1 || !request.additional_allocations.is_empty() {
        return Err(AdmissionRefusal::AtomicBundleRequired);
    }
    let ExactTimeContext {
        offering,
        exact,
        members,
        open,
        closures,
        snapshot,
        policy_revision,
        now,
    } = context;

    if request.policy_revision != *policy_revision {
        return Err(AdmissionRefusal::PolicyChanged);
    }
    check_horizon(
        request.start,
        *now,
        exact.lead_time_minutes,
        exact.horizon_days,
    )?;

    match request.party {
        Some(party)
            if party.is_coherent()
                && party.recipients <= exact.maximum_recipients
                && (!exact.party_counts.is_required() || party.recipients > 0) => {}
        None if !exact.party_counts.is_required() => {}
        _ => return Err(AdmissionRefusal::PartyCapacityInadequate),
    }
    check_capabilities(offering, request)?;
    check_prerequisites(offering, request)?;
    check_duplicate(offering, request, snapshot, exclude, *now)?;

    let duration_minutes = exact
        .selected_duration_minutes(request.duration_minutes)
        .ok_or(AdmissionRefusal::DurationOutOfPolicy)?;
    if request.resource.is_some() && !exact.allow_resource_selection {
        return Err(AdmissionRefusal::ResourceSelectionNotAllowed);
    }

    // Interval arithmetic that leaves representable time is a horizon
    // refusal, never a mislabeled capacity answer: a start whose service or
    // occupied interval cannot exist is outside every bookable horizon.
    let end = request
        .start
        .checked_add_signed(Duration::minutes(i64::from(duration_minutes)))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        })?;

    // Buffers reaching past representable time refuse rather than clamp: a
    // clamped buffer would silently shrink the occupied interval the ledger
    // records.
    let occupied_start = request
        .start
        .checked_sub_signed(Duration::minutes(i64::from(exact.buffer_before_minutes)))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooSoon,
        })?;
    let occupied_end = end
        .checked_add_signed(Duration::minutes(i64::from(exact.buffer_after_minutes)))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        })?;
    let (coverage_start, coverage_end) = match exact.opening_coverage {
        OpeningCoverage::ServiceInterval => (request.start, end),
        OpeningCoverage::OccupiedInterval => (occupied_start, occupied_end),
    };
    let covered = open
        .iter()
        .find(|interval| interval.start <= coverage_start && coverage_end <= interval.end);
    let Some(covering) = covered else {
        let overlaps_closure = closures
            .iter()
            .any(|closure| coverage_start < closure.end && closure.start < coverage_end);
        return Err(if overlaps_closure {
            AdmissionRefusal::LocationClosed
        } else {
            AdmissionRefusal::ScheduleUnpublished
        });
    };
    // The start grid is part of the published schedule: the offering serves
    // starts at fixed increments from the opening's start. A zero increment
    // publishes no grid at all, so every start is off it; the check refuses
    // zero, and the evaluator still refuses to divide by it rather than trust
    // its caller. Alignment is exact: a start inside the minute after a grid
    // point, whatever seconds it carries, is off the grid availability
    // publishes.
    let offset = request.start.signed_duration_since(covering.start);
    let grid_seconds = i64::from(exact.start_increment_minutes) * 60;
    let on_grid = offset >= Duration::zero()
        && grid_seconds != 0
        && offset.subsec_nanos() == 0
        && offset.num_seconds() % grid_seconds == 0;
    if !on_grid {
        return Err(AdmissionRefusal::ScheduleUnpublished);
    }

    let candidate_members: Vec<&PoolMember> = if let Some(selected) = request.resource.as_deref() {
        let member = members
            .iter()
            .find(|member| member.resource_id == selected)
            .ok_or(AdmissionRefusal::ResourceNotInPool)?;
        vec![member]
    } else {
        members.iter().collect()
    };
    let capable: Vec<&PoolMember> = candidate_members
        .into_iter()
        .filter(|member| member.serves(&offering.requires_capabilities))
        .collect();
    if capable.is_empty() {
        return Err(AdmissionRefusal::CapabilityUnmatched);
    }
    let available: Vec<&PoolMember> = capable
        .iter()
        .copied()
        .filter(|member| {
            member.capacity_units > 0 && member.available_during(occupied_start, occupied_end)
        })
        .collect();
    if available.is_empty() {
        return Err(AdmissionRefusal::ResourceUnavailable);
    }

    let mut free: Vec<&PoolMember> = available
        .iter()
        .copied()
        .filter(|member| {
            !snapshot.supply_occupied(
                &member.resource_id,
                occupied_start,
                occupied_end,
                exclude,
                *now,
            )
        })
        .collect();
    if free.is_empty() {
        return Err(AdmissionRefusal::CapacityExhausted);
    }
    // Deterministic selection: the same state always picks the same member,
    // so replay and explain agree with the runtime's commit.
    free.sort_by_key(|member| member.resource_id.clone());

    let chosen = free[0];
    Ok(Admission {
        offering: offering.id.clone(),
        start: request.start,
        end,
        occupied_start,
        occupied_end,
        resource: Some(chosen.resource_id.clone()),
        units: 1,
    })
}

#[derive(Clone, Debug)]
struct ResolvedBundleLine {
    requirement_id: String,
    offering: String,
    interval: AllocationInterval,
    requirement: AllocationRequirement,
}

/// Evaluate every exact-time line against one displayed interval and one
/// standing snapshot, then allocate physical quantities atomically.
pub fn evaluate_exact_time_bundle(
    context: &ExactTimeBundleContext<'_>,
    request: &AdmissionRequest,
) -> Result<BundleAdmission, BundleEvaluationError> {
    if context.lines.len() != request.additional_allocations.len() + 1 {
        return Err(BundleEvaluationError::Shape);
    }
    let Some(primary) = context.lines.first() else {
        return Err(BundleEvaluationError::Shape);
    };
    if primary.requirement_id != "primary"
        || primary.offering.id != request.offering
        || primary.resource != request.resource.as_deref()
        || primary.units != request.resource_units
    {
        return Err(BundleEvaluationError::Shape);
    }
    let displayed_duration = primary
        .exact
        .selected_duration_minutes(request.duration_minutes)
        .ok_or(AdmissionRefusal::DurationOutOfPolicy)?;

    let mut resolved = Vec::with_capacity(context.lines.len());
    for (index, line) in context.lines.iter().enumerate() {
        if index > 0 {
            let additional = &request.additional_allocations[index - 1];
            if line.offering.id != additional.offering
                || line.resource != additional.resource.as_deref()
                || line.units != additional.units
                || line.requirement_id != format!("additional:{}", index - 1)
            {
                return Err(BundleEvaluationError::Shape);
            }
            check_additional_allocation_policy(
                primary.offering,
                line.offering,
                displayed_duration,
            )?;
        }
        resolved.push(resolve_bundle_line(
            line,
            request,
            displayed_duration,
            context.snapshot,
            context.policy_revision,
            context.now,
            context.exclude_reservation,
            context.confirming_hold,
        )?);
    }

    allocate_resolved_bundle(
        context,
        &primary.offering.id,
        request.start,
        displayed_duration,
        resolved,
    )
}

/// Resolve and atomically allocate the physical requirements for a displayed
/// exact-time interval.
///
/// The caller must separately enforce caller eligibility, policy revision,
/// duplicate protection, and booking horizon. This evaluator is shared by
/// availability preview and window resource reservation, where those
/// request-specific facts either do not exist or are checked by the owning
/// workflow.
pub fn evaluate_exact_time_physical_bundle(
    context: &ExactTimeBundleContext<'_>,
    start: DateTime<Utc>,
    displayed_duration: u32,
) -> Result<BundleAdmission, BundleEvaluationError> {
    let Some(primary) = context.lines.first() else {
        return Err(BundleEvaluationError::Shape);
    };
    let mut resolved = Vec::with_capacity(context.lines.len());
    for (index, line) in context.lines.iter().enumerate() {
        if index > 0 {
            check_additional_allocation_policy(
                primary.offering,
                line.offering,
                displayed_duration,
            )?;
        }
        resolved.push(resolve_physical_bundle_line(
            line,
            start,
            displayed_duration,
        )?);
    }
    allocate_resolved_bundle(
        context,
        &primary.offering.id,
        start,
        displayed_duration,
        resolved,
    )
}

fn allocate_resolved_bundle(
    context: &ExactTimeBundleContext<'_>,
    primary_offering: &str,
    start: DateTime<Utc>,
    displayed_duration: u32,
    resolved: Vec<ResolvedBundleLine>,
) -> Result<BundleAdmission, BundleEvaluationError> {
    let standing_allocations = context
        .snapshot
        .consuming(context.now)
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
    let allocation = allocate_bundle(&AllocationContext {
        requirements: resolved
            .iter()
            .map(|line| line.requirement.clone())
            .collect(),
        standing_allocations,
        exclude_reservation: context.exclude_reservation.map(str::to_owned),
        limits: context.limits,
    })?;
    let mut allocations: Vec<_> = allocation
        .into_iter()
        .map(|allocated: AllocatedResource| {
            let line = resolved
                .iter()
                .find(|line| line.requirement_id == allocated.requirement_id)
                .expect("the allocator returns only input requirement identifiers");
            BundleAllocation {
                requirement_id: allocated.requirement_id,
                offering: line.offering.clone(),
                resource: allocated.resource_id,
                units: allocated.units,
                occupied_start: line.interval.start,
                occupied_end: line.interval.end,
            }
        })
        .collect();
    allocations.sort_by_key(|allocation| {
        if allocation.requirement_id == "primary" {
            0
        } else {
            allocation
                .requirement_id
                .strip_prefix("additional:")
                .and_then(|index| index.parse::<usize>().ok())
                .unwrap_or(usize::MAX - 1)
                .saturating_add(1)
        }
    });
    Ok(BundleAdmission {
        offering: primary_offering.to_owned(),
        start,
        end: start
            .checked_add_signed(Duration::minutes(i64::from(displayed_duration)))
            .ok_or(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooFar,
            })?,
        allocations,
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_bundle_line(
    line: &ExactTimeBundleLineContext<'_>,
    request: &AdmissionRequest,
    displayed_duration: u32,
    snapshot: &LedgerSnapshot,
    policy_revision: u64,
    now: DateTime<Utc>,
    exclude: Option<&str>,
    confirming_hold: bool,
) -> Result<ResolvedBundleLine, AdmissionRefusal> {
    if request.policy_revision != policy_revision {
        return Err(AdmissionRefusal::PolicyChanged);
    }
    if !confirming_hold {
        check_horizon(
            request.start,
            now,
            line.exact.lead_time_minutes,
            line.exact.horizon_days,
        )?;
    }
    match request.party {
        Some(party)
            if party.is_coherent()
                && party.recipients <= line.exact.maximum_recipients
                && (!line.exact.party_counts.is_required() || party.recipients > 0) => {}
        None if !line.exact.party_counts.is_required() => {}
        _ => return Err(AdmissionRefusal::PartyCapacityInadequate),
    }
    check_capabilities(line.offering, request)?;
    check_prerequisites(line.offering, request)?;
    check_duplicate(line.offering, request, snapshot, exclude, now)?;
    resolve_physical_bundle_line(line, request.start, displayed_duration)
}

fn resolve_physical_bundle_line(
    line: &ExactTimeBundleLineContext<'_>,
    start: DateTime<Utc>,
    displayed_duration: u32,
) -> Result<ResolvedBundleLine, AdmissionRefusal> {
    if line
        .exact
        .selected_duration_minutes(Some(displayed_duration))
        .is_none()
    {
        return Err(AdmissionRefusal::DurationOutOfPolicy);
    }
    if line.resource.is_some() && !line.stored_resource && !line.exact.allow_resource_selection {
        return Err(AdmissionRefusal::ResourceSelectionNotAllowed);
    }
    let end = start
        .checked_add_signed(Duration::minutes(i64::from(displayed_duration)))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        })?;
    let occupied_start = start
        .checked_sub_signed(Duration::minutes(i64::from(
            line.exact.buffer_before_minutes,
        )))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooSoon,
        })?;
    let occupied_end = end
        .checked_add_signed(Duration::minutes(i64::from(
            line.exact.buffer_after_minutes,
        )))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        })?;
    let (coverage_start, coverage_end) = match line.exact.opening_coverage {
        OpeningCoverage::ServiceInterval => (start, end),
        OpeningCoverage::OccupiedInterval => (occupied_start, occupied_end),
    };
    let Some(covering) = line
        .open
        .iter()
        .find(|interval| interval.start <= coverage_start && coverage_end <= interval.end)
    else {
        return Err(
            if line
                .closures
                .iter()
                .any(|closure| closure.start < coverage_end && coverage_start < closure.end)
            {
                AdmissionRefusal::LocationClosed
            } else {
                AdmissionRefusal::ScheduleUnpublished
            },
        );
    };
    let offset = start.signed_duration_since(covering.start);
    let grid_seconds = i64::from(line.exact.start_increment_minutes) * 60;
    if offset < Duration::zero()
        || grid_seconds == 0
        || offset.subsec_nanos() != 0
        || offset.num_seconds() % grid_seconds != 0
    {
        return Err(AdmissionRefusal::ScheduleUnpublished);
    }

    let candidate_members: Vec<&PoolMember> = if let Some(selected) = line.resource {
        vec![line
            .members
            .iter()
            .find(|member| member.resource_id == selected)
            .ok_or(AdmissionRefusal::ResourceNotInPool)?]
    } else {
        line.members.iter().collect()
    };
    let capable: Vec<&PoolMember> = candidate_members
        .into_iter()
        .filter(|member| member.serves(&line.offering.requires_capabilities))
        .collect();
    if capable.is_empty() {
        return Err(AdmissionRefusal::CapabilityUnmatched);
    }
    let available: Vec<&PoolMember> = capable
        .into_iter()
        .filter(|member| {
            member.capacity_units > 0 && member.available_during(occupied_start, occupied_end)
        })
        .collect();
    if available.is_empty() {
        return Err(AdmissionRefusal::ResourceUnavailable);
    }
    let interval = AllocationInterval {
        start: occupied_start,
        end: occupied_end,
    };
    Ok(ResolvedBundleLine {
        requirement_id: line.requirement_id.clone(),
        offering: line.offering.id.clone(),
        interval: interval.clone(),
        requirement: AllocationRequirement {
            id: line.requirement_id.clone(),
            interval,
            units: line.units,
            candidates: available
                .into_iter()
                .map(|member| AllocationCandidate {
                    resource_id: member.resource_id.clone(),
                    capacity_units: member.capacity_units,
                })
                .collect(),
        },
    })
}

/// Evaluate one arrival-window admission request.
///
/// The window's units policy converts the party to recipient units; the
/// channel subquota and the total window capacity are both checked, and a
/// party the published units could never carry is refused as inadequate
/// rather than as exhausted.
///
/// `exclude` carries the same meaning it carries for an exact-time request:
/// the one standing claim this request replaces, supplied by the runtime or
/// by offline replay and never by a caller.
pub fn evaluate_window_admission(
    context: &WindowContext<'_>,
    request: &AdmissionRequest,
    exclude: Option<&str>,
) -> Result<Admission, AdmissionRefusal> {
    if request.resource_units != 1 || !request.additional_allocations.is_empty() {
        return Err(AdmissionRefusal::AtomicBundleRequired);
    }
    let WindowContext {
        offering,
        window,
        open,
        closures,
        lead_time_minutes,
        horizon_days,
        snapshot,
        policy_revision,
        channels,
        now,
    } = context;

    if request.policy_revision != *policy_revision {
        return Err(AdmissionRefusal::PolicyChanged);
    }
    if request.duration_minutes.is_some() {
        return Err(AdmissionRefusal::DurationOutOfPolicy);
    }
    if request.resource.is_some() {
        return Err(AdmissionRefusal::ResourceSelectionNotAllowed);
    }
    if request.window_revision != Some(window.revision) {
        return Err(AdmissionRefusal::RevisionMismatch {
            observed: window.revision,
        });
    }
    check_horizon(window.start, *now, *lead_time_minutes, *horizon_days)?;
    if request.start != window.start {
        return Err(AdmissionRefusal::ScheduleUnpublished);
    }
    let covered = open
        .iter()
        .any(|interval| interval.start <= window.start && window.end <= interval.end);
    if !covered {
        let overlaps_closure = closures
            .iter()
            .any(|closure| window.start < closure.end && closure.start < window.end);
        return Err(if overlaps_closure {
            AdmissionRefusal::LocationClosed
        } else {
            AdmissionRefusal::ScheduleUnpublished
        });
    }

    let Some(party) = request.party else {
        return Err(AdmissionRefusal::PartyCapacityInadequate);
    };
    if !party.is_coherent() || party.recipients == 0 {
        return Err(AdmissionRefusal::PartyCapacityInadequate);
    }
    let required = window
        .units_policy
        .evaluate(party.recipients)
        .map_err(|error| match error {
            UnitsEvaluationError::RefusedAboveHighestBand | UnitsEvaluationError::Overflow => {
                AdmissionRefusal::PartyCapacityInadequate
            }
        })?;
    if required > window.units {
        return Err(AdmissionRefusal::PartyCapacityInadequate);
    }
    check_capabilities(offering, request)?;
    check_prerequisites(offering, request)?;
    check_duplicate(offering, request, snapshot, exclude, *now)?;

    if let Some(name) = &request.channel {
        // The channel vocabulary is closed, and the channels the policy
        // declares narrow it to the served subset. A name outside either
        // would match no subquota and draw from the window's total
        // unconstrained, so it is refused before any capacity is counted. An
        // empty declaration serves no channel: the reader refuses one, and
        // this check fails closed if a policy ever arrives without it.
        let channel = Channel::from_name(name).ok_or(AdmissionRefusal::ChannelUnknown)?;
        if !channels.contains(&channel) {
            return Err(AdmissionRefusal::ChannelUnknown);
        }
        if let Some(subquota) = window
            .subquotas
            .iter()
            .find(|subquota| subquota.channel == channel)
        {
            let allocated = snapshot.window_units_allocated(&window.id, Some(name), exclude, *now);
            if allocated.saturating_add(required) > subquota.units {
                return Err(AdmissionRefusal::CapacityExhausted);
            }
        }
    }
    let allocated = snapshot.window_units_allocated(&window.id, None, exclude, *now);
    if allocated.saturating_add(required) > window.units {
        return Err(AdmissionRefusal::CapacityExhausted);
    }

    Ok(Admission {
        offering: offering.id.clone(),
        start: window.start,
        end: window.end,
        occupied_start: window.start,
        occupied_end: window.end,
        resource: None,
        units: required,
    })
}

/// Evaluate a hold's state at an instant.
///
/// An active hold confirms. A hold that expired at or before `now` is
/// expired, whatever the cleanup worker has or has not done. A claim that is
/// not a hold at all (a booking, or a hold already released or consumed) is
/// not confirmable; release and consumption are store states the runtime
/// reports with `hold.released` when it resolves the claim, so seeing one
/// here means the caller passed the wrong claim.
pub fn evaluate_hold_state(
    hold: &LedgerClaim,
    now: DateTime<Utc>,
) -> Result<&LedgerClaim, AdmissionRefusal> {
    if hold.kind != LedgerKind::Hold {
        return Err(AdmissionRefusal::HoldReleased);
    }
    match hold.expires_at {
        Some(expiry) if expiry > now => Ok(hold),
        _ => Err(AdmissionRefusal::HoldExpired),
    }
}

fn check_horizon(
    start: DateTime<Utc>,
    now: DateTime<Utc>,
    lead_time_minutes: u32,
    horizon_days: u32,
) -> Result<(), AdmissionRefusal> {
    let lead = start.signed_duration_since(now);
    if lead < Duration::minutes(i64::from(lead_time_minutes)) {
        return Err(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooSoon,
        });
    }
    if lead > Duration::minutes(i64::from(horizon_days) * 24 * 60) {
        return Err(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        });
    }
    Ok(())
}

fn check_prerequisites(
    offering: &OfferingPolicy,
    request: &AdmissionRequest,
) -> Result<(), AdmissionRefusal> {
    let missing: Vec<String> = offering
        .prerequisites
        .iter()
        .filter(|wanted| !request.prerequisites.contains(wanted))
        .cloned()
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AdmissionRefusal::PrerequisiteMissing { missing })
    }
}

fn check_capabilities(
    offering: &OfferingPolicy,
    request: &AdmissionRequest,
) -> Result<(), AdmissionRefusal> {
    if offering
        .requires_capabilities
        .iter()
        .all(|wanted| request.capabilities.contains(wanted))
    {
        Ok(())
    } else {
        Err(AdmissionRefusal::CapabilityUnmatched)
    }
}

fn check_duplicate(
    offering: &OfferingPolicy,
    request: &AdmissionRequest,
    snapshot: &LedgerSnapshot,
    exclude: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), AdmissionRefusal> {
    if offering.duplicate_active_key.is_none() {
        return Ok(());
    }
    match &request.duplicate_key {
        // An offering that keys duplicate actives refuses a request without a
        // key: skipping the check would let the same party hold two active
        // bookings by omission.
        None => Err(AdmissionRefusal::DuplicateKeyRequired),
        Some(key) if snapshot.duplicate_active(&offering.id, key, exclude, now) => {
            Err(AdmissionRefusal::DuplicateActiveBooking)
        }
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        ArrivalOffering, Channel, DurationSelectionPolicy, ExactTimeOffering, OfferingPolicy,
        OpeningCoverage, PublishedWindow, SchedulingMode, WindowSubquota,
    };
    use crate::units::{BandedInput, RequiredUnitsPolicy};
    use crate::{PartyCounts, PartyCountsRequirement};
    use chrono::TimeZone as _;
    use registry_platform_calendar::{
        expand_weekly_openings, CalendarException, CalendarExceptionKind, HolidaySetRevision,
        WeeklyOpeningPattern,
    };

    fn utc(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, hour, minute, 0)
            .unwrap()
    }

    /// The shared pool membership, computed once and borrowed for the
    /// lifetime of every context the tests build.
    fn members() -> &'static [PoolMember] {
        static MEMBERS: std::sync::OnceLock<Vec<PoolMember>> = std::sync::OnceLock::new();
        MEMBERS.get_or_init(|| {
            vec![
                PoolMember {
                    resource_id: "station-1".to_owned(),
                    capabilities: vec![],
                    available: true,
                    capacity_units: 1,
                    availability: None,
                },
                PoolMember {
                    resource_id: "station-2".to_owned(),
                    capabilities: vec![],
                    available: true,
                    capacity_units: 1,
                    availability: None,
                },
            ]
        })
    }

    fn exact_offering() -> (OfferingPolicy, ExactTimeOffering) {
        (
            OfferingPolicy {
                id: "registry-update-30".to_owned(),
                service: "registry-update".to_owned(),
                label: "30-minute counter update".to_owned(),
                mode: SchedulingMode::ExactTime,
                location: "north-counter".to_owned(),
                because: "A 30-minute update at an interchangeable station.".to_owned(),
                exact_time: None,
                arrival: None,
                cancellation_cutoff_minutes: 240,
                reminders: Vec::new(),
                duplicate_active_key: Some("subject".to_owned()),
                requires_capabilities: Vec::new(),
                prerequisites: Vec::new(),
            },
            ExactTimeOffering {
                duration_minutes: 30,
                duration_selection: None,
                opening_coverage: OpeningCoverage::ServiceInterval,
                allow_resource_selection: false,
                party_counts: PartyCountsRequirement::Required,
                buffer_before_minutes: 5,
                buffer_after_minutes: 5,
                lead_time_minutes: 60,
                horizon_days: 30,
                pool: "update-stations".to_owned(),
                start_increment_minutes: 30,
                maximum_recipients: 1,
            },
        )
    }

    #[test]
    fn dated_resource_supply_controls_the_whole_occupied_interval() {
        let at = |hour, minute| utc(10, hour, minute);
        let scheduled: PoolMember = serde_json::from_value(serde_json::json!({
            "resourceId": "station-1", "capabilities": [], "available": true,
            "availability": {
                "openings": [
                    {"start": "2026-10-10T01:30:00Z", "end": "2026-10-10T03:00:00Z"},
                    {"start": "2026-10-10T03:00:00Z", "end": "2026-10-10T04:30:00Z"}
                ],
                "closures": [{"start": "2026-10-10T09:50:00+07:00", "end": "2026-10-10T10:20:00+07:00"}]
            }
        })).expect("a resource may carry dated supply facts");
        let mut available_members = members().to_vec();
        available_members[0] = scheduled;
        let (offering, mut exact) = exact_offering();
        exact.allow_resource_selection = true;
        let open = [CalendarInterval {
            start: at(2, 0),
            end: at(4, 0),
        }];
        let snapshot = LedgerSnapshot::default();
        let context = ExactTimeContext {
            offering: &offering,
            exact: &exact,
            members: &available_members,
            open: &open,
            closures: &[],
            snapshot: &snapshot,
            policy_revision: 1,
            now: at(0, 0),
        };
        let blocked = exact_request(at(2, 30));
        let allocation = evaluate_exact_time_admission(&context, &blocked, None).unwrap();
        assert_eq!(allocation.resource.as_deref(), Some("station-2"));
        let named = AdmissionRequest {
            resource: Some("station-1".to_owned()),
            ..blocked
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &named, None).unwrap_err(),
            AdmissionRefusal::ResourceUnavailable
        );
        for start in [at(2, 0), at(3, 30)] {
            let request = AdmissionRequest {
                start,
                ..named.clone()
            };
            assert_eq!(
                evaluate_exact_time_admission(&context, &request, None)
                    .unwrap()
                    .resource
                    .as_deref(),
                Some("station-1")
            );
        }
        // Cleanup touches the closure even though the displayed service does
        // not. Dated supply always constrains effective occupancy.
        let mut buffered = exact.clone();
        buffered.buffer_after_minutes = 25;
        let context = ExactTimeContext {
            exact: &buffered,
            ..context
        };
        let request = AdmissionRequest {
            start: at(2, 0),
            ..named
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None).unwrap_err(),
            AdmissionRefusal::ResourceUnavailable
        );
    }

    #[test]
    fn exact_time_refuses_zero_physical_capacity_even_when_the_member_is_available() {
        let (offering, exact) = exact_offering();
        let zero_capacity = [PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: Vec::new(),
            available: true,
            capacity_units: 0,
            availability: None,
        }];
        let snapshot = LedgerSnapshot::default();
        let context = exact_context(&offering, &exact, &zero_capacity, &snapshot, utc(5, 0, 0));

        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 3, 0)), None),
            Err(AdmissionRefusal::ResourceUnavailable)
        );
    }

    /// The shared published openings, computed once and borrowed for the
    /// lifetime of every context the tests build.
    fn open_intervals() -> &'static [CalendarInterval] {
        static OPEN: std::sync::OnceLock<Vec<CalendarInterval>> = std::sync::OnceLock::new();
        OPEN.get_or_init(|| {
            vec![
                CalendarInterval {
                    start: utc(5, 2, 0),
                    end: utc(5, 5, 30),
                },
                CalendarInterval {
                    start: utc(6, 2, 0),
                    end: utc(6, 5, 30),
                },
            ]
        })
    }

    fn exact_context<'a>(
        offering: &'a OfferingPolicy,
        exact: &'a ExactTimeOffering,
        members: &'a [PoolMember],
        snapshot: &'a LedgerSnapshot,
        now: DateTime<Utc>,
    ) -> ExactTimeContext<'a> {
        ExactTimeContext {
            offering,
            exact,
            members,
            open: open_intervals(),
            closures: &[],
            snapshot,
            policy_revision: 1,
            now,
        }
    }

    fn exact_request(start: DateTime<Utc>) -> AdmissionRequest {
        AdmissionRequest {
            offering: "registry-update-30".to_owned(),
            start,
            duration_minutes: None,
            resource: None,
            resource_units: 1,
            additional_allocations: Vec::new(),
            party: Some(PartyCounts {
                recipients: 1,
                attendees: 1,
            }),
            manager: None,
            channel: None,
            duplicate_key: Some("subject:one".to_owned()),
            policy_revision: 1,
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
            external_references: Vec::new(),
            party_references: Vec::new(),
        }
    }

    fn bundle_limits() -> AllocationLimits {
        AllocationLimits {
            maximum_requirements: 16,
            maximum_units_per_requirement: 10_000,
            maximum_candidate_resources: 256,
            maximum_standing_allocations: 256,
        }
    }

    #[test]
    fn a_bundle_uses_each_lines_occupied_interval_and_half_open_boundaries() {
        let (mut room, mut room_exact) = exact_offering();
        room.id = "room".to_owned();
        room.duplicate_active_key = None;
        room_exact.duration_minutes = 120;
        room_exact.party_counts = PartyCountsRequirement::Optional;
        room_exact.buffer_before_minutes = 15;
        room_exact.buffer_after_minutes = 15;
        room_exact.allow_resource_selection = true;
        room_exact.pool = "rooms".to_owned();
        room.exact_time = Some(room_exact.clone());

        let mut projector = room.clone();
        projector.id = "projector".to_owned();
        let mut projector_exact = room_exact.clone();
        projector_exact.buffer_before_minutes = 0;
        projector_exact.buffer_after_minutes = 0;
        projector_exact.pool = "projectors".to_owned();
        projector.exact_time = Some(projector_exact.clone());
        let room_members = [PoolMember {
            resource_id: "room-a".to_owned(),
            capabilities: Vec::new(),
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let projector_members = [PoolMember {
            resource_id: "projector-a".to_owned(),
            capabilities: Vec::new(),
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let open = [CalendarInterval {
            start: utc(5, 2, 0),
            end: utc(5, 6, 0),
        }];
        let request = AdmissionRequest {
            offering: "room".to_owned(),
            start: utc(5, 3, 0),
            duration_minutes: Some(120),
            resource: Some("room-a".to_owned()),
            resource_units: 1,
            additional_allocations: vec![crate::AdditionalAllocationRequest {
                offering: "projector".to_owned(),
                resource: Some("projector-a".to_owned()),
                units: 1,
            }],
            party: None,
            manager: None,
            channel: None,
            duplicate_key: None,
            policy_revision: 1,
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
            external_references: Vec::new(),
            party_references: Vec::new(),
        };
        let lines = [
            ExactTimeBundleLineContext {
                requirement_id: "primary".to_owned(),
                offering: &room,
                exact: &room_exact,
                members: &room_members,
                open: &open,
                closures: &[],
                resource: Some("room-a"),
                stored_resource: false,
                units: 1,
            },
            ExactTimeBundleLineContext {
                requirement_id: "additional:0".to_owned(),
                offering: &projector,
                exact: &projector_exact,
                members: &projector_members,
                open: &open,
                closures: &[],
                resource: Some("projector-a"),
                stored_resource: false,
                units: 1,
            },
        ];
        let snapshot = LedgerSnapshot {
            claims: vec![
                booking_claim(
                    "projector-before",
                    "projector-a",
                    utc(5, 2, 0),
                    utc(5, 3, 0),
                ),
                booking_claim("room-overlap", "room-a", utc(5, 2, 30), utc(5, 3, 0)),
            ],
        };
        let context = ExactTimeBundleContext {
            lines: &lines,
            snapshot: &snapshot,
            policy_revision: 1,
            now: utc(5, 0, 0),
            exclude_reservation: None,
            confirming_hold: false,
            limits: bundle_limits(),
        };
        assert_eq!(
            evaluate_exact_time_bundle(&context, &request),
            Err(BundleEvaluationError::Allocation(
                AllocationError::CapacityExhausted {
                    requirement_id: "primary".to_owned()
                }
            ))
        );

        let snapshot = LedgerSnapshot {
            claims: snapshot.claims[..1].to_vec(),
        };
        let context = ExactTimeBundleContext {
            lines: &lines,
            snapshot: &snapshot,
            policy_revision: 1,
            now: utc(5, 0, 0),
            exclude_reservation: None,
            confirming_hold: false,
            limits: bundle_limits(),
        };
        let admitted = evaluate_exact_time_bundle(&context, &request).unwrap();
        assert_eq!(admitted.allocations[0].occupied_start, utc(5, 2, 45));
        assert_eq!(admitted.allocations[0].occupied_end, utc(5, 5, 15));
        assert_eq!(admitted.allocations[1].occupied_start, utc(5, 3, 0));
        assert_eq!(admitted.allocations[1].occupied_end, utc(5, 5, 0));
    }

    #[test]
    fn physical_bundle_evaluation_does_not_invent_caller_eligibility() {
        let (mut offering, mut exact) = exact_offering();
        offering.requires_capabilities = vec!["interpreter".to_owned()];
        offering.prerequisites = vec!["proof".to_owned()];
        exact.party_counts = PartyCountsRequirement::Required;
        let capable = [PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: vec!["interpreter".to_owned()],
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let lines = [ExactTimeBundleLineContext {
            requirement_id: "primary".to_owned(),
            offering: &offering,
            exact: &exact,
            members: &capable,
            open: open_intervals(),
            closures: &[],
            resource: None,
            stored_resource: false,
            units: 1,
        }];
        let snapshot = LedgerSnapshot::default();
        let context = ExactTimeBundleContext {
            lines: &lines,
            snapshot: &snapshot,
            policy_revision: 1,
            now: utc(5, 0, 0),
            exclude_reservation: None,
            confirming_hold: false,
            limits: bundle_limits(),
        };

        let admitted = evaluate_exact_time_physical_bundle(&context, utc(5, 3, 0), 30)
            .expect("physical planning must not require a party, prerequisite, or duplicate key");
        assert_eq!(admitted.allocations.len(), 1);
        assert_eq!(admitted.allocations[0].resource, "station-1");

        let request = AdmissionRequest {
            capabilities: vec!["interpreter".to_owned()],
            prerequisites: vec!["proof".to_owned()],
            duplicate_key: None,
            ..exact_request(utc(5, 3, 0))
        };
        assert_eq!(
            evaluate_exact_time_bundle(&context, &request),
            Err(BundleEvaluationError::Admission(
                AdmissionRefusal::DuplicateKeyRequired
            )),
            "actual booking evaluation keeps the caller admission checks"
        );
    }

    #[test]
    fn the_legacy_evaluators_refuse_bundle_fields_instead_of_ignoring_them() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let context = exact_context(&offering, &exact, members(), &snapshot, utc(5, 0, 0));
        let request = AdmissionRequest {
            resource_units: 2,
            ..exact_request(utc(5, 3, 0))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None),
            Err(AdmissionRefusal::AtomicBundleRequired)
        );
    }

    #[test]
    fn exact_time_omits_people_only_when_policy_explicitly_allows_it() {
        let (offering, mut exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let request = AdmissionRequest {
            party: None,
            ..exact_request(utc(5, 3, 0))
        };
        let required = exact_context(&offering, &exact, members(), &snapshot, utc(5, 0, 0));
        assert_eq!(
            evaluate_exact_time_admission(&required, &request, None),
            Err(AdmissionRefusal::PartyCapacityInadequate)
        );

        exact.party_counts = PartyCountsRequirement::Optional;
        let optional = exact_context(&offering, &exact, members(), &snapshot, utc(5, 0, 0));
        let admitted = evaluate_exact_time_admission(&optional, &request, None)
            .expect("an explicitly party-optional resource reservation admits");
        assert_eq!(admitted.units, 1);
    }

    #[test]
    fn exact_time_refuses_incoherent_people_even_when_counts_are_optional() {
        let (offering, mut exact) = exact_offering();
        exact.party_counts = PartyCountsRequirement::Optional;
        let snapshot = LedgerSnapshot::default();
        let context = exact_context(&offering, &exact, members(), &snapshot, utc(5, 0, 0));
        for party in [
            PartyCounts {
                recipients: 2,
                attendees: 1,
            },
            PartyCounts {
                recipients: 0,
                attendees: 0,
            },
        ] {
            let request = AdmissionRequest {
                party: Some(party),
                ..exact_request(utc(5, 3, 0))
            };
            assert_eq!(
                evaluate_exact_time_admission(&context, &request, None),
                Err(AdmissionRefusal::PartyCapacityInadequate)
            );
        }
    }

    fn selectable_duration() -> DurationSelectionPolicy {
        DurationSelectionPolicy {
            minimum_minutes: 15,
            maximum_minutes: 60,
            increment_minutes: 15,
        }
    }

    fn booking_claim(
        id: &str,
        supply: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> LedgerClaim {
        LedgerClaim {
            id: id.to_owned(),
            offering: "registry-update-30".to_owned(),
            supply_id: supply.to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start,
            end,
            units: 1,
            duplicate_key: None,
            expires_at: None,
        }
    }

    fn window_claim(id: &str, units: u32, channel: &str) -> LedgerClaim {
        LedgerClaim {
            id: id.to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some(channel.to_owned()),
            start: utc(10, 8, 0),
            end: utc(10, 10, 0),
            units,
            duplicate_key: None,
            expires_at: None,
        }
    }

    /// AT-01, pure half: two callers against the last free unit. The first is
    /// admitted onto a concrete member; the second, replayed against the
    /// ledger the first created, is refused with a recoverable conflict.
    #[test]
    fn the_second_caller_against_the_last_unit_is_refused() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        let first = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None)
            .expect("the first caller is admitted");
        assert_eq!(first.resource.as_deref(), Some("station-1"));

        let mut after = snapshot.clone();
        after.claims.push(booking_claim(
            "claim-1",
            "station-1",
            first.occupied_start,
            first.occupied_end,
        ));
        let second_context = exact_context(&offering, &exact, members(), &after, now);
        let second =
            evaluate_exact_time_admission(&second_context, &exact_request(utc(5, 2, 30)), None)
                .map(|admission| admission.resource)
                .map_err(|refusal| refusal.public_code());
        assert_eq!(second, Ok(Some("station-2".to_owned())));

        // With one station left occupied at the same displayed time, the
        // other station serves; once both are occupied the refusal is a
        // recoverable capacity conflict.
        after.claims.push(booking_claim(
            "claim-2",
            "station-2",
            utc(5, 2, 25),
            utc(5, 3, 5),
        ));
        let third_context = exact_context(&offering, &exact, members(), &after, now);
        let third =
            evaluate_exact_time_admission(&third_context, &exact_request(utc(5, 2, 30)), None);
        assert_eq!(
            third.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );
    }

    /// AT-09: buffers make touching displayed times conflict.
    #[test]
    fn buffer_overlap_rejects_touching_displayed_times() {
        let (offering, exact) = exact_offering();
        let mut snapshot = LedgerSnapshot::default();
        // Claims on both stations displayed 02:00-02:30, occupied 01:55-02:35.
        snapshot.claims.push(booking_claim(
            "claim-1",
            "station-1",
            utc(5, 1, 55),
            utc(5, 2, 35),
        ));
        snapshot.claims.push(booking_claim(
            "claim-2",
            "station-2",
            utc(5, 1, 55),
            utc(5, 2, 35),
        ));
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        // A 02:30 start displays as touching, but its 02:25 buffer start
        // overlaps both claims' cleanup, so every member is blocked.
        let result = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None);
        assert_eq!(
            result.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );

        // At 03:00, with the increment grid observed, both stations are free.
        let result = evaluate_exact_time_admission(&context, &exact_request(utc(5, 3, 0)), None);
        assert!(result.is_ok());
    }

    #[test]
    fn omitted_interval_and_resource_preserve_fixed_duration_fungible_selection() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        let admission =
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None)
                .expect("legacy request admits");
        assert_eq!(admission.end, utc(5, 3, 0));
        assert_eq!(admission.resource.as_deref(), Some("station-1"));
    }

    #[test]
    fn requested_interval_must_be_on_the_authored_duration_lattice() {
        let (offering, mut exact) = exact_offering();
        exact.duration_selection = Some(selectable_duration());
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        for duration_minutes in [14, 16, 61] {
            let request = AdmissionRequest {
                duration_minutes: Some(duration_minutes),
                ..exact_request(utc(5, 2, 30))
            };
            assert_eq!(
                evaluate_exact_time_admission(&context, &request, None).err(),
                Some(AdmissionRefusal::DurationOutOfPolicy),
                "duration {duration_minutes} must be refused"
            );
        }

        let request = AdmissionRequest {
            duration_minutes: Some(45),
            ..exact_request(utc(5, 2, 30))
        };
        let admission = evaluate_exact_time_admission(&context, &request, None)
            .expect("an allowed duration admits");
        assert_eq!(admission.end, utc(5, 3, 15));
    }

    #[test]
    fn exact_resource_selection_never_falls_back_to_another_member() {
        let (offering, mut exact) = exact_offering();
        exact.allow_resource_selection = true;
        let members = vec![
            PoolMember {
                resource_id: "station-1".to_owned(),
                capabilities: Vec::new(),
                available: true,
                capacity_units: 1,
                availability: None,
            },
            PoolMember {
                resource_id: "station-2".to_owned(),
                capabilities: Vec::new(),
                available: false,
                capacity_units: 1,
                availability: None,
            },
        ];
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, &members, &snapshot, now);

        let unavailable = AdmissionRequest {
            resource: Some("station-2".to_owned()),
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &unavailable, None).err(),
            Some(AdmissionRefusal::ResourceUnavailable)
        );

        let outside_pool = AdmissionRequest {
            resource: Some("station-3".to_owned()),
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &outside_pool, None).err(),
            Some(AdmissionRefusal::ResourceNotInPool)
        );
    }

    #[test]
    fn selected_member_must_carry_the_offerings_capabilities() {
        let (mut offering, mut exact) = exact_offering();
        exact.allow_resource_selection = true;
        offering.requires_capabilities = vec!["notary".to_owned()];
        let members = vec![
            PoolMember {
                resource_id: "station-1".to_owned(),
                capabilities: Vec::new(),
                available: true,
                capacity_units: 1,
                availability: None,
            },
            PoolMember {
                resource_id: "station-2".to_owned(),
                capabilities: vec!["notary".to_owned()],
                available: true,
                capacity_units: 1,
                availability: None,
            },
        ];
        let snapshot = LedgerSnapshot::default();
        let context = exact_context(&offering, &exact, &members, &snapshot, utc(4, 4, 0));
        let request = AdmissionRequest {
            capabilities: vec!["notary".to_owned()],
            resource: Some("station-1".to_owned()),
            ..exact_request(utc(5, 2, 30))
        };

        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None).err(),
            Some(AdmissionRefusal::CapabilityUnmatched)
        );
    }

    #[test]
    fn selected_member_buffer_conflict_refuses_instead_of_falling_back() {
        let (offering, mut exact) = exact_offering();
        exact.allow_resource_selection = true;
        let snapshot = LedgerSnapshot {
            claims: vec![booking_claim(
                "claim-1",
                "station-2",
                utc(5, 1, 55),
                utc(5, 2, 35),
            )],
        };
        let context = exact_context(&offering, &exact, members(), &snapshot, utc(4, 4, 0));
        let request = AdmissionRequest {
            resource: Some("station-2".to_owned()),
            ..exact_request(utc(5, 2, 30))
        };

        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None).err(),
            Some(AdmissionRefusal::CapacityExhausted)
        );
    }

    #[test]
    fn named_resource_is_refused_unless_the_offering_opts_in() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let context = exact_context(&offering, &exact, members(), &snapshot, utc(4, 4, 0));
        let request = AdmissionRequest {
            resource: Some("station-1".to_owned()),
            ..exact_request(utc(5, 2, 30))
        };

        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None).err(),
            Some(AdmissionRefusal::ResourceSelectionNotAllowed)
        );
    }

    #[test]
    fn service_interval_coverage_preserves_buffered_boundary_slots() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let opening = [CalendarInterval {
            start: utc(5, 2, 0),
            end: utc(5, 3, 0),
        }];
        let closures = [
            CalendarInterval {
                start: utc(5, 1, 55),
                end: utc(5, 2, 0),
            },
            CalendarInterval {
                start: utc(5, 3, 0),
                end: utc(5, 3, 5),
            },
        ];
        let context = ExactTimeContext {
            open: &opening,
            closures: &closures,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        let first = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 0)), None)
            .expect("the first displayed slot admits");
        assert_eq!(first.occupied_start, utc(5, 1, 55));
        let last = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None)
            .expect("the last displayed slot admits");
        assert_eq!(last.occupied_end, utc(5, 3, 5));
    }

    #[test]
    fn occupied_interval_coverage_rejects_buffers_outside_openings_or_in_closures() {
        let (offering, mut exact) = exact_offering();
        exact.opening_coverage = OpeningCoverage::OccupiedInterval;
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let opening = [CalendarInterval {
            start: utc(5, 2, 0),
            end: utc(5, 3, 0),
        }];
        let context = ExactTimeContext {
            open: &opening,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 0)), None).err(),
            Some(AdmissionRefusal::ScheduleUnpublished),
            "the setup buffer starts before the opening"
        );

        let closure = [CalendarInterval {
            start: utc(5, 3, 0),
            end: utc(5, 3, 5),
        }];
        let opening = [CalendarInterval {
            start: utc(5, 2, 0),
            end: utc(5, 3, 0),
        }];
        let context = ExactTimeContext {
            open: &opening,
            closures: &closure,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None).err(),
            Some(AdmissionRefusal::LocationClosed),
            "the cleanup buffer overlaps the closure"
        );
    }

    /// AT-06, duplicate half: the same subject with an active booking is
    /// refused; a reschedule of that booking excludes itself.
    #[test]
    fn an_active_duplicate_key_is_refused_unless_rescheduling_it() {
        let (offering, exact) = exact_offering();
        let mut snapshot = LedgerSnapshot::default();
        let mut existing = booking_claim("claim-1", "station-1", utc(5, 1, 55), utc(5, 2, 35));
        existing.duplicate_key = Some("subject:one".to_owned());
        snapshot.claims.push(existing);
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        let fresh = evaluate_exact_time_admission(&context, &exact_request(utc(5, 3, 0)), None);
        assert_eq!(
            fresh.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::BookingDuplicateActive)
        );

        let moved =
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 3, 0)), Some("claim-1"));
        assert!(moved.is_ok(), "{moved:?}");
    }

    /// A keyed offering refuses a request without a duplicate key: the
    /// duplicate check may not be skipped by omission.
    #[test]
    fn a_keyed_offering_refuses_a_request_without_a_duplicate_key() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        let request = AdmissionRequest {
            duplicate_key: None,
            ..exact_request(utc(5, 2, 30))
        };
        let refusal = evaluate_exact_time_admission(&context, &request, None)
            .expect_err("refused for the missing key");
        assert_eq!(refusal.public_code(), ProblemCode::PreconditionRequired);
        assert_eq!(refusal.detailed_code(), ProblemCode::PreconditionRequired);
    }

    /// Interval arithmetic that leaves representable time refuses as a
    /// horizon answer: never a mislabeled capacity refusal, never a silently
    /// clamped buffer that undercounts occupancy.
    #[test]
    fn unrepresentable_intervals_refuse_as_horizon_never_as_capacity() {
        let (offering, mut exact) = exact_offering();
        exact.lead_time_minutes = 1;
        exact.horizon_days = 3650;
        let snapshot = LedgerSnapshot::default();

        // A start whose displayed end leaves representable time.
        let now = DateTime::<Utc>::MAX_UTC - Duration::minutes(10);
        let at_the_edge = now + Duration::minutes(5);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(at_the_edge), None).err(),
            Some(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooFar
            })
        );

        // A displayed interval that fits, whose cleanup buffer does not.
        let now = DateTime::<Utc>::MAX_UTC - Duration::minutes(60);
        let start = DateTime::<Utc>::MAX_UTC - Duration::minutes(30);
        assert!(start.checked_add_signed(Duration::minutes(30)).is_some());
        exact.buffer_after_minutes = 30;
        let open = [CalendarInterval {
            start: now,
            end: DateTime::<Utc>::MAX_UTC,
        }];
        let context = ExactTimeContext {
            open: &open,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(start), None).err(),
            Some(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooFar
            })
        );

        // A start whose setup buffer reaches before representable time.
        let now = DateTime::<Utc>::MIN_UTC + Duration::minutes(1);
        let start = DateTime::<Utc>::MIN_UTC + Duration::minutes(2);
        let open = [CalendarInterval {
            start,
            end: start + Duration::minutes(30),
        }];
        let context = ExactTimeContext {
            open: &open,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(start), None).err(),
            Some(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooSoon
            })
        );
    }

    /// A zero increment publishes no grid at all; the evaluator refuses every
    /// start rather than dividing by zero. The policy check refuses zero, and
    /// this holds the line for hand-built contexts.
    #[test]
    fn a_zero_increment_grid_serves_no_start() {
        let (offering, mut exact) = exact_offering();
        exact.start_increment_minutes = 0;
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 30)), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );
    }

    /// Grid alignment is exact, not minute-truncated: a start inside the
    /// minute after a grid point is off the grid availability publishes,
    /// whatever seconds it carries.
    #[test]
    fn a_start_inside_the_minute_after_a_grid_point_is_off_the_grid() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        let grid_point = utc(5, 2, 30);
        assert!(
            evaluate_exact_time_admission(&context, &exact_request(grid_point), None).is_ok(),
            "the grid point itself admits"
        );
        for off_grid in [
            grid_point + Duration::seconds(45),
            grid_point + Duration::milliseconds(500),
            grid_point + Duration::minutes(29) + Duration::seconds(59),
        ] {
            assert_eq!(
                evaluate_exact_time_admission(&context, &exact_request(off_grid), None)
                    .err()
                    .map(|refusal| refusal.public_code()),
                Some(ProblemCode::ScheduleUnpublished),
                "a start off the grid by less than a minute is still off it: {off_grid}"
            );
        }
    }

    /// Self-overlap: a reschedule onto its own current slot succeeds, because
    /// its own allocation is excluded, while another caller at that slot is
    /// refused.
    #[test]
    fn a_reschedule_does_not_compete_with_its_own_allocation() {
        let (offering, exact) = exact_offering();
        let mut snapshot = LedgerSnapshot::default();
        let mut existing = booking_claim("claim-1", "station-1", utc(5, 1, 55), utc(5, 2, 35));
        existing.duplicate_key = Some("subject:one".to_owned());
        snapshot.claims.push(existing);
        // Both stations hold the slot, so only the reschedule's own exclusion
        // can get a caller onto 02:00.
        snapshot.claims.push(booking_claim(
            "claim-2",
            "station-2",
            utc(5, 1, 55),
            utc(5, 2, 35),
        ));
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        // The exclusion is the evaluator's own argument, not something the
        // request carries, so this is the shape the runtime calls.
        let result =
            evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 0)), Some("claim-1"));
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap().resource.as_deref(), Some("station-1"));

        // The identical request without the exclusion is refused, which is
        // what a create path is: no caller can ask for one.
        let other = AdmissionRequest {
            duplicate_key: Some("subject:two".to_owned()),
            ..exact_request(utc(5, 2, 0))
        };
        let result = evaluate_exact_time_admission(&context, &other, None);
        assert_eq!(
            result.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );
    }

    /// AT-05, pure half: an expired hold consumes nothing, and confirming it
    /// late is refused.
    #[test]
    fn an_expired_hold_consumes_nothing_and_cannot_be_confirmed() {
        let now = utc(4, 4, 0);
        let expired_hold = LedgerClaim {
            id: "hold-1".to_owned(),
            offering: "registry-update-30".to_owned(),
            supply_id: "station-1".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(5, 1, 55),
            end: utc(5, 2, 35),
            units: 1,
            duplicate_key: Some("subject:one".to_owned()),
            expires_at: Some(utc(4, 3, 55)),
        };
        let snapshot = LedgerSnapshot {
            claims: vec![expired_hold.clone()],
        };

        assert_eq!(
            evaluate_hold_state(&expired_hold, now).err(),
            Some(AdmissionRefusal::HoldExpired)
        );

        let (offering, exact) = exact_offering();
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        // The expired hold neither blocks the slot nor blocks the duplicate
        // key: its capacity is bookable again.
        let result = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 0)), None);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn a_live_hold_still_consumes() {
        let now = utc(4, 4, 0);
        let live_hold = LedgerClaim {
            id: "hold-1".to_owned(),
            offering: "registry-update-30".to_owned(),
            supply_id: "station-1".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(5, 1, 55),
            end: utc(5, 2, 35),
            units: 1,
            duplicate_key: None,
            expires_at: Some(utc(4, 4, 30)),
        };
        assert!(evaluate_hold_state(&live_hold, now).is_ok());

        let snapshot = LedgerSnapshot {
            claims: vec![live_hold],
        };
        let (offering, exact) = exact_offering();
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        let result = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 0)), None);
        // station-1 is held; station-2 still serves the party.
        assert_eq!(
            result.map(|admission| admission.resource),
            Ok(Some("station-2".to_owned()))
        );
    }

    /// BKG-02: a public refusal distinguishes horizon, closure, unpublished
    /// schedule, capability, and party bounds; and never names an unavailable
    /// resource.
    #[test]
    fn refusals_carry_their_distinguished_public_codes() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);

        // Too soon: 02:00 is inside the 60-minute lead time at 04:00? No: it
        // is in the past, which is the strongest form of too soon.
        let past = evaluate_exact_time_admission(&context, &exact_request(utc(4, 4, 30)), None);
        assert!(matches!(
            past.err(),
            Some(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooSoon
            })
        ));

        // Beyond the 30-day horizon: November 10 is 36 days out.
        let far = AdmissionRequest {
            start: Utc.with_ymd_and_hms(2026, 11, 10, 2, 30, 0).unwrap(),
            ..exact_request(utc(5, 2, 30))
        };
        assert!(matches!(
            evaluate_exact_time_admission(&context, &far, None).err(),
            Some(AdmissionRefusal::HorizonOutside {
                kind: HorizonKind::TooFar
            })
        ));

        // Off-grid start: no published schedule serves 02:15.
        let off_grid = evaluate_exact_time_admission(&context, &exact_request(utc(5, 2, 15)), None);
        assert_eq!(
            off_grid.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );

        // Off the published day entirely.
        let unpublished_day =
            evaluate_exact_time_admission(&context, &exact_request(utc(9, 2, 30)), None);
        assert_eq!(
            unpublished_day.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );

        // A closure over the start is a closure, not an unpublished day. The
        // expansion has already removed the closure from the published
        // openings, so the uncovered start overlaps the closure interval.
        let closures = vec![CalendarInterval {
            start: utc(5, 2, 0),
            end: utc(5, 3, 0),
        }];
        let open_after_closure = [CalendarInterval {
            start: utc(5, 3, 0),
            end: utc(5, 5, 30),
        }];
        let closed_context = ExactTimeContext {
            open: &open_after_closure,
            closures: &closures,
            ..exact_context(&offering, &exact, members(), &snapshot, now)
        };
        let closed =
            evaluate_exact_time_admission(&closed_context, &exact_request(utc(5, 2, 30)), None);
        assert_eq!(
            closed.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::LocationClosed)
        );

        // A party larger than the offering can ever serve.
        let party = AdmissionRequest {
            party: Some(PartyCounts {
                recipients: 2,
                attendees: 2,
            }),
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &party, None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::PartyCapacityInadequate)
        );

        // A required capability no member carries.
        let (wanting, exact_wanting) = {
            let (mut offering, exact) = exact_offering();
            offering.requires_capabilities = vec!["interpreter".to_owned()];
            (offering, exact)
        };
        let capable_members = vec![PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: vec!["notary".to_owned()],
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let wanting_context =
            exact_context(&wanting, &exact_wanting, &capable_members, &snapshot, now);
        let capable_request = AdmissionRequest {
            capabilities: vec!["interpreter".to_owned()],
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&wanting_context, &capable_request, None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapabilityUnmatched)
        );

        // The request must carry the offering capability too; a capable
        // backing member does not make up for a party that lacks it.
        let available = vec![PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: vec!["interpreter".to_owned()],
            available: true,
            capacity_units: 1,
            availability: None,
        }];
        let available_context = exact_context(&wanting, &exact_wanting, &available, &snapshot, now);
        assert_eq!(
            evaluate_exact_time_admission(&available_context, &exact_request(utc(5, 2, 30)), None,)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapabilityUnmatched)
        );

        // Capable members that are all unavailable: the public answer is
        // exhausted capacity, the detailed answer names unavailability.
        let unavailable = vec![PoolMember {
            resource_id: "station-1".to_owned(),
            capabilities: vec!["interpreter".to_owned()],
            available: false,
            capacity_units: 1,
            availability: None,
        }];
        let unavailable_context =
            exact_context(&wanting, &exact_wanting, &unavailable, &snapshot, now);
        let refused = evaluate_exact_time_admission(&unavailable_context, &capable_request, None)
            .expect_err("refused");
        assert_eq!(refused.public_code(), ProblemCode::CapacityExhausted);
        assert_eq!(refused.detailed_code(), ProblemCode::ResourceUnavailable);
    }

    #[test]
    fn policy_change_outranks_a_window_revision_mismatch() {
        let (offering, exact) = exact_offering();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        let stale = AdmissionRequest {
            policy_revision: 0,
            window_revision: Some(7),
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &stale, None).err(),
            Some(AdmissionRefusal::PolicyChanged)
        );
    }

    #[test]
    fn missing_prerequisites_are_named() {
        let (mut offering, exact) = exact_offering();
        offering.prerequisites = vec![
            "case:approved-application".to_owned(),
            "urn:evidence:residency".to_owned(),
        ];
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 4, 0);
        let context = exact_context(&offering, &exact, members(), &snapshot, now);
        let request = AdmissionRequest {
            prerequisites: vec!["urn:evidence:residency".to_owned()],
            ..exact_request(utc(5, 2, 30))
        };
        assert_eq!(
            evaluate_exact_time_admission(&context, &request, None).err(),
            Some(AdmissionRefusal::PrerequisiteMissing {
                missing: vec!["case:approved-application".to_owned()]
            })
        );
    }

    fn window() -> PublishedWindow {
        PublishedWindow {
            id: "household-morning-window".to_owned(),
            revision: 2,
            offering: "household-morning".to_owned(),
            location: "civic-hall".to_owned(),
            start: utc(10, 8, 0),
            end: utc(10, 10, 0),
            units: 3,
            units_policy: RequiredUnitsPolicy::PerRecipient {
                per_recipient: 1,
                because: "Each recipient consumes one serving slot.".to_owned(),
            },
            subquotas: vec![WindowSubquota {
                id: "public-quota".to_owned(),
                channel: Channel::Public,
                units: 2,
                because: "Most households book the public channel.".to_owned(),
            }],
            leftover: None,
            staffing: None,
            resources: Vec::new(),
            because: "The Saturday morning household block.".to_owned(),
        }
    }

    fn arrival_offering() -> OfferingPolicy {
        OfferingPolicy {
            id: "household-morning".to_owned(),
            service: "household-day".to_owned(),
            label: "Morning household block".to_owned(),
            mode: SchedulingMode::ArrivalWindow,
            location: "civic-hall".to_owned(),
            because: "Households arrive in a served morning block.".to_owned(),
            exact_time: None,
            arrival: Some(ArrivalOffering {
                window: Some("household-morning-window".to_owned()),
                lead_time_minutes: 1,
                horizon_days: 60,
            }),
            cancellation_cutoff_minutes: 1440,
            reminders: Vec::new(),
            duplicate_active_key: None,
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        }
    }

    /// Every channel the vocabulary holds, for contexts that test something
    /// other than the channel declaration.
    const ALL_CHANNELS: &[Channel] = &[
        Channel::Public,
        Channel::Assisted,
        Channel::Urgent,
        Channel::WalkIn,
    ];

    fn window_request(recipients: u32, attendees: u32) -> AdmissionRequest {
        AdmissionRequest {
            offering: "household-morning".to_owned(),
            start: utc(10, 8, 0),
            duration_minutes: None,
            resource: None,
            resource_units: 1,
            additional_allocations: Vec::new(),
            party: Some(PartyCounts {
                recipients,
                attendees,
            }),
            manager: None,
            channel: Some("public".to_owned()),
            duplicate_key: None,
            policy_revision: 1,
            window_revision: Some(2),
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
            external_references: Vec::new(),
            party_references: Vec::new(),
        }
    }

    fn published_window_interval(window: &PublishedWindow) -> [CalendarInterval; 1] {
        [CalendarInterval {
            start: window.start,
            end: window.end,
        }]
    }

    /// AT-03: three attendees with two recipients consume two units, never
    /// three.
    #[test]
    fn attendee_count_never_becomes_consumed_units() {
        let offering = arrival_offering();
        let window = window();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        let admission =
            evaluate_window_admission(&context, &window_request(2, 3), None).expect("admitted");
        assert_eq!(admission.units, 2);
    }

    /// AT-02: a two-recipient party against one remaining unit is refused
    /// without a partial or undercounted booking.
    #[test]
    fn a_party_that_does_not_fit_remaining_capacity_is_refused_whole() {
        let offering = arrival_offering();
        let window = window();
        let snapshot = LedgerSnapshot {
            claims: vec![window_claim("claim-1", 2, "public")],
        };
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        let result = evaluate_window_admission(&context, &window_request(2, 2), None);
        assert_eq!(
            result.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );

        // The one remaining unit sits outside the public slice: a caller the
        // window does not channel still fits it.
        let unchanneled = AdmissionRequest {
            channel: None,
            ..window_request(1, 1)
        };
        let single = evaluate_window_admission(&context, &unchanneled, None);
        assert_eq!(single.map(|admission| admission.units), Ok(1));
    }

    #[test]
    fn an_arrival_window_requires_the_partys_capabilities() {
        let mut offering = arrival_offering();
        offering.requires_capabilities = vec!["interpreter".to_owned()];
        let window = window();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        let missing = evaluate_window_admission(&context, &window_request(1, 1), None);
        assert_eq!(
            missing.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapabilityUnmatched)
        );
        let held = AdmissionRequest {
            capabilities: vec!["interpreter".to_owned()],
            ..window_request(1, 1)
        };
        assert!(evaluate_window_admission(&context, &held, None).is_ok());
    }

    #[test]
    fn a_party_the_published_units_could_never_carry_is_inadequate_not_exhausted() {
        let offering = arrival_offering();
        let mut window = window();
        window.units = 2;
        window.units_policy = RequiredUnitsPolicy::BandedTable {
            input: BandedInput::ServiceRecipientCount,
            bands: vec![crate::units::UnitBand {
                up_to: 2,
                units: 2,
                because: "A household of two shares one block.".to_owned(),
            }],
            above_highest_band: crate::units::AboveHighestBand::Refuse {},
            because: "Household sizing reviewed in 2026.".to_owned(),
        };
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        // Four recipients are above the highest band: inadequate party.
        assert_eq!(
            evaluate_window_admission(&context, &window_request(4, 4), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::PartyCapacityInadequate)
        );
        // Two recipients fall in the band at 2 units, exactly the published 2:
        // admitted, not inadequate.
        assert!(evaluate_window_admission(&context, &window_request(2, 2), None).is_ok());
    }

    #[test]
    fn subquota_channels_are_checked_before_the_total() {
        let offering = arrival_offering();
        let window = window();
        // Public subquota of 2, already fully allocated.
        let snapshot = LedgerSnapshot {
            claims: vec![window_claim("claim-1", 2, "public")],
        };
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        let result = evaluate_window_admission(&context, &window_request(1, 1), None);
        assert_eq!(
            result.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );
    }

    /// COR-3 / D5(a): the channel vocabulary is closed, and the channels a
    /// policy declares narrow it further. A spelling
    /// outside the vocabulary, or a vocabulary member the deployment does
    /// not serve, once matched no subquota and drew from the window's total
    /// unconstrained.
    #[test]
    fn a_channel_the_policy_does_not_serve_is_refused_not_let_loose() {
        let offering = arrival_offering();
        let window = window();
        // Public subquota of 2, already fully allocated.
        let snapshot = LedgerSnapshot {
            claims: vec![window_claim("claim-1", 2, "public")],
        };
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        // The vocabulary itself refuses a misspelled channel: "Public" is
        // not a channel any subquota can name, so it may not book as one.
        let misspelled = AdmissionRequest {
            channel: Some("Public".to_owned()),
            ..window_request(1, 1)
        };
        assert_eq!(
            evaluate_window_admission(&context, &misspelled, None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::RequestUnprocessable)
        );

        // A policy that declares only the public channel refuses a request
        // naming another vocabulary member, whatever its slice would be.
        let narrowed = WindowContext {
            channels: &[Channel::Public],
            ..context
        };
        let undeclared = AdmissionRequest {
            channel: Some("urgent".to_owned()),
            ..window_request(1, 1)
        };
        assert_eq!(
            evaluate_window_admission(&narrowed, &undeclared, None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::RequestUnprocessable)
        );

        // The declared channel itself still meets its subquota: the public
        // slice is full, so the same refusal the plain test expects.
        assert_eq!(
            evaluate_window_admission(&narrowed, &window_request(1, 1), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );

        // A declaration that serves no channel fails closed: every named
        // channel is refused, never let loose on the window's total.
        let unserved = WindowContext {
            channels: &[],
            ..context
        };
        assert_eq!(
            evaluate_window_admission(&unserved, &window_request(1, 1), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::RequestUnprocessable)
        );
    }

    #[test]
    fn window_revisions_must_match_and_policy_change_wins() {
        let offering = arrival_offering();
        let window = window();
        let snapshot = LedgerSnapshot::default();
        let now = utc(4, 9, 0);
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now,
        };
        let stale_window = AdmissionRequest {
            window_revision: Some(1),
            ..window_request(1, 1)
        };
        assert!(matches!(
            evaluate_window_admission(&context, &stale_window, None).err(),
            Some(AdmissionRefusal::RevisionMismatch { observed: 2 })
        ));

        let stale_both = AdmissionRequest {
            policy_revision: 0,
            ..stale_window
        };
        assert_eq!(
            evaluate_window_admission(&context, &stale_both, None).err(),
            Some(AdmissionRefusal::PolicyChanged)
        );
    }

    #[test]
    fn window_request_start_must_match_the_published_window() {
        let offering = arrival_offering();
        let window = window();
        let snapshot = LedgerSnapshot::default();
        let open = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &open,
            closures: &[],
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now: utc(4, 9, 0),
        };
        let request = AdmissionRequest {
            start: utc(4, 10, 30),
            ..window_request(1, 1)
        };

        assert_eq!(
            evaluate_window_admission(&context, &request, None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );
    }

    #[test]
    fn window_outside_openings_distinguishes_closure_from_unpublished_schedule() {
        let offering = arrival_offering();
        let window = window();
        let snapshot = LedgerSnapshot::default();
        let closure = published_window_interval(&window);
        let context = WindowContext {
            offering: &offering,
            window: &window,
            open: &[],
            closures: &closure,
            lead_time_minutes: 1,
            horizon_days: 60,
            snapshot: &snapshot,
            policy_revision: 1,
            channels: ALL_CHANNELS,
            now: utc(4, 9, 0),
        };

        assert_eq!(
            evaluate_window_admission(&context, &window_request(1, 1), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::LocationClosed)
        );

        let uncovered = WindowContext {
            closures: &[],
            ..context
        };
        assert_eq!(
            evaluate_window_admission(&uncovered, &window_request(1, 1), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );
    }

    /// AT-19: opening expansion across a daylight-saving fold feeds admission
    /// with real elapsed intervals, and the repeated wall-clock hour yields two
    /// distinct bookable instants, never an invisible duplicate.
    #[test]
    fn the_folded_hour_yields_two_distinct_bookable_instants() {
        // America/New_York falls back on 2026-11-01: local 01:30 occurs twice,
        // at 05:30Z EDT and 06:30Z EST. A pattern may not start or end inside
        // the repeated hour, but it may span the fold: the hall opens
        // 00:30-02:30 local, whose endpoints exist unambiguously. The two
        // wall-clock hours span three real hours, [04:30Z, 07:30Z).
        let pattern = WeeklyOpeningPattern {
            id: "fold-day-hours",
            timezone: "America/New_York",
            weekdays: &[chrono::Weekday::Sun],
            start_time: "00:30",
            end_time: "02:30",
            effective_from: "2026-11-01",
            effective_until: "2026-11-01",
        };
        let holidays = HolidaySetRevision {
            holiday_set: "office-holidays",
            revision: 1,
            dates: &[],
        };
        let open = expand_weekly_openings(&pattern, &[], &holidays).expect("expands");
        assert_eq!(open.len(), 1);
        assert_eq!(
            open[0].start,
            Utc.with_ymd_and_hms(2026, 11, 1, 4, 30, 0).unwrap()
        );
        assert_eq!(
            open[0].end,
            Utc.with_ymd_and_hms(2026, 11, 1, 7, 30, 0).unwrap()
        );
        assert_eq!((open[0].end - open[0].start).num_minutes(), 180);

        let (offering, mut exact) = exact_offering();
        exact.lead_time_minutes = 1;
        exact.horizon_days = 3650;
        exact.start_increment_minutes = 30;
        exact.duration_minutes = 30;
        exact.duration_selection = Some(DurationSelectionPolicy {
            minimum_minutes: 30,
            maximum_minutes: 60,
            increment_minutes: 30,
        });
        let snapshot = LedgerSnapshot::default();
        let now = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
        let context = ExactTimeContext {
            offering: &offering,
            exact: &exact,
            members: members(),
            open: &open,
            closures: &[],
            snapshot: &snapshot,
            policy_revision: 1,
            now,
        };
        // Both 01:30 instants are on the grid and inside the real interval:
        // the first (EDT) takes a selected 60 minutes and ends at the second
        // 01:30 instant, while the second (EST) uses the 30-minute default.
        let first_request = AdmissionRequest {
            duration_minutes: Some(60),
            ..exact_request(Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap())
        };
        let first = evaluate_exact_time_admission(&context, &first_request, None)
            .expect("the first 01:30 admits");
        assert_eq!(
            first.end,
            Utc.with_ymd_and_hms(2026, 11, 1, 6, 30, 0).unwrap()
        );
        let second = evaluate_exact_time_admission(
            &context,
            &exact_request(Utc.with_ymd_and_hms(2026, 11, 1, 6, 30, 0).unwrap()),
            None,
        )
        .expect("the second 01:30 admits");
        assert_eq!(
            second.end,
            Utc.with_ymd_and_hms(2026, 11, 1, 7, 0, 0).unwrap()
        );

        // A start at the interval's end is outside the real opening: no
        // published schedule serves it, whatever the wall clock says.
        let outside = Utc.with_ymd_and_hms(2026, 11, 1, 7, 30, 0).unwrap();
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(outside), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::ScheduleUnpublished)
        );
    }

    /// A closure applied during expansion removes the bookable interval, and
    /// the evaluator reports the closure, not an unpublished schedule.
    #[test]
    fn a_closure_over_a_fold_day_interval_closes_the_slot() {
        // Same fold-day opening, [04:30Z, 07:30Z). A closure before the fold
        // whose endpoints sit in one offset, 00:15-00:45 local, removes the
        // first half hour: the opening starts 04:45Z, and a request inside the
        // closed stretch reports the closure.
        let pattern = WeeklyOpeningPattern {
            id: "fold-day-hours",
            timezone: "America/New_York",
            weekdays: &[chrono::Weekday::Sun],
            start_time: "00:30",
            end_time: "02:30",
            effective_from: "2026-11-01",
            effective_until: "2026-11-01",
        };
        let holidays = HolidaySetRevision {
            holiday_set: "office-holidays",
            revision: 1,
            dates: &[],
        };
        let closure = CalendarException {
            id: "systems-training",
            kind: CalendarExceptionKind::Closure,
            date: "2026-11-01",
            start_time: "00:15",
            end_time: "00:45",
            reopens: None,
            authority: None,
        };
        let open = expand_weekly_openings(&pattern, &[closure], &holidays).expect("expands");
        assert_eq!(open.len(), 1);
        assert_eq!(
            open[0].start,
            Utc.with_ymd_and_hms(2026, 11, 1, 4, 45, 0).unwrap()
        );

        let (offering, mut exact) = exact_offering();
        exact.lead_time_minutes = 1;
        exact.horizon_days = 3650;
        let snapshot = LedgerSnapshot::default();
        let now = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
        let closures = vec![CalendarInterval {
            start: Utc.with_ymd_and_hms(2026, 11, 1, 4, 15, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 11, 1, 4, 45, 0).unwrap(),
        }];
        let context = ExactTimeContext {
            offering: &offering,
            exact: &exact,
            members: members(),
            open: &open,
            closures: &closures,
            snapshot: &snapshot,
            policy_revision: 1,
            now,
        };
        // Inside the closed stretch: a closure, not an unpublished schedule.
        let closed_start = Utc.with_ymd_and_hms(2026, 11, 1, 4, 30, 0).unwrap();
        assert_eq!(
            evaluate_exact_time_admission(&context, &exact_request(closed_start), None)
                .err()
                .map(|refusal| refusal.public_code()),
            Some(ProblemCode::LocationClosed)
        );
        // On the moved grid (increments from 04:45Z) the hall still serves.
        let served = evaluate_exact_time_admission(
            &context,
            &exact_request(Utc.with_ymd_and_hms(2026, 11, 1, 5, 15, 0).unwrap()),
            None,
        )
        .expect("the post-closure grid serves");
        assert_eq!(
            served.end,
            Utc.with_ymd_and_hms(2026, 11, 1, 5, 45, 0).unwrap()
        );
    }
}
