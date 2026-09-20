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

use crate::model::{AdmissionRequest, LedgerClaim, LedgerKind, LedgerSnapshot, PoolMember};
use crate::policy::{Channel, ExactTimeOffering, OfferingPolicy, PublishedWindow};
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
    #[error("an active booking already holds this party's duplicate key")]
    DuplicateActiveBooking,
    #[error("the offering keys duplicate actives, so the request must carry a key")]
    DuplicateKeyRequired,
    #[error("every capable member is unavailable")]
    ResourceUnavailable,
    #[error("the supply is fully committed for that interval")]
    CapacityExhausted,
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
    /// itself is closed; a declaration narrows it to the served subset, and
    /// a request naming a channel outside either is refused before any
    /// capacity is counted. An empty slice declares nothing beyond the
    /// vocabulary.
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

    if request.party.recipients == 0 || request.party.recipients > exact.max_recipients {
        return Err(AdmissionRefusal::PartyCapacityInadequate);
    }
    check_capabilities(offering, request)?;
    check_prerequisites(offering, request)?;
    check_duplicate(offering, request, snapshot, exclude, *now)?;

    // Interval arithmetic that leaves representable time is a horizon
    // refusal, never a mislabeled capacity answer: a start whose service or
    // occupied interval cannot exist is outside every bookable horizon.
    let end = request
        .start
        .checked_add_signed(Duration::minutes(i64::from(exact.duration_minutes)))
        .ok_or(AdmissionRefusal::HorizonOutside {
            kind: HorizonKind::TooFar,
        })?;
    let covered = open
        .iter()
        .find(|interval| interval.start <= request.start && end <= interval.end);
    let Some(covering) = covered else {
        let overlaps_closure = closures
            .iter()
            .any(|closure| request.start < closure.end && closure.start < end);
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

    let capable: Vec<&PoolMember> = members
        .iter()
        .filter(|member| member.serves(&offering.requires_capabilities))
        .collect();
    if capable.is_empty() {
        return Err(AdmissionRefusal::CapabilityUnmatched);
    }
    let available: Vec<&PoolMember> = capable
        .iter()
        .copied()
        .filter(|member| member.available)
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

    if request.party.recipients == 0 {
        return Err(AdmissionRefusal::PartyCapacityInadequate);
    }
    let required = window
        .units_policy
        .evaluate(request.party.recipients)
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
        // The channel vocabulary is closed, and a policy that declares the
        // channels it serves narrows it further. A name outside either once
        // matched no subquota and drew from the window's total unconstrained,
        // so it is refused before any capacity is counted.
        let channel = Channel::from_name(name).ok_or(AdmissionRefusal::ChannelUnknown)?;
        if !channels.is_empty() && !channels.contains(&channel) {
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
    use crate::model::PartyCounts;
    use crate::policy::{
        ArrivalOffering, Channel, ExactTimeOffering, OfferingPolicy, PublishedWindow,
        SchedulingMode, WindowSubquota,
    };
    use crate::units::{BandedInput, RequiredUnitsPolicy};
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
                },
                PoolMember {
                    resource_id: "station-2".to_owned(),
                    capabilities: vec![],
                    available: true,
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
                buffer_before_minutes: 5,
                buffer_after_minutes: 5,
                lead_time_minutes: 60,
                horizon_days: 30,
                pool: "update-stations".to_owned(),
                start_increment_minutes: 30,
                max_recipients: 1,
            },
        )
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
            party: PartyCounts {
                recipients: 1,
                attendees: 1,
            },
            channel: None,
            duplicate_key: Some("subject:one".to_owned()),
            policy_revision: 1,
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
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
            party: PartyCounts {
                recipients: 2,
                attendees: 2,
            },
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
                window: "household-morning-window".to_owned(),
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

    fn window_request(recipients: u32, attendees: u32) -> AdmissionRequest {
        AdmissionRequest {
            offering: "household-morning".to_owned(),
            start: utc(10, 8, 0),
            party: PartyCounts {
                recipients,
                attendees,
            },
            channel: Some("public".to_owned()),
            duplicate_key: None,
            policy_revision: 1,
            window_revision: Some(2),
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
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
            channels: &[],
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
            channels: &[],
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
            channels: &[],
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
            above_highest_band: crate::units::AboveHighestBand::Refuse,
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
            channels: &[],
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
            channels: &[],
            now,
        };
        let result = evaluate_window_admission(&context, &window_request(1, 1), None);
        assert_eq!(
            result.err().map(|refusal| refusal.public_code()),
            Some(ProblemCode::CapacityExhausted)
        );
    }

    /// COR-3 / D5(a): the channel vocabulary is closed, and a policy that
    /// declares the channels it serves narrows it further. A spelling
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
            channels: &[],
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
            channels: &[],
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
            channels: &[],
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
            channels: &[],
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
        // the first (EDT) ends 06:00Z, the second (EST) ends 07:00Z.
        let first = evaluate_exact_time_admission(
            &context,
            &exact_request(Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap()),
            None,
        )
        .expect("the first 01:30 admits");
        assert_eq!(
            first.end,
            Utc.with_ymd_and_hms(2026, 11, 1, 6, 0, 0).unwrap()
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
