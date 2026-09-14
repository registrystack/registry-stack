// SPDX-License-Identifier: Apache-2.0

//! The source-neutral scheduling model: lifecycle states, the authoritative
//! supply ledger, the environment records admission runs against, and the
//! admission request with its idempotent request hash.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use registry_platform_calendar::{CalendarException, CalendarExceptionKind};

/// Lifecycle of a temporary hold. An expired hold stops consuming capacity the
/// moment it expires, whether or not a cleanup worker has run since.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HoldState {
    Active,
    Consumed,
    Released,
    Expired,
}

/// Lifecycle of a confirmed booking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BookingState {
    Confirmed,
    Cancelled,
}

/// Recorded attendance of a booking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AttendanceState {
    NotRecorded,
    Arrived,
    InService,
    Completed,
    NoShow,
    LeftWithoutService,
}

/// The party summary capacity is derived from. Recipients are the people the
/// service is delivered to; attendees are everyone present, recipients
/// included. A parent accompanying two children is three attendees and two
/// recipients, and consumes recipient units, never attendee counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartyCounts {
    pub recipients: u32,
    pub attendees: u32,
}

/// What a ledger entry allocates supply for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerKind {
    /// A confirmed booking.
    Booking,
    /// A temporary hold.
    Hold,
}

/// One entry in the authoritative supply ledger.
///
/// `start` and `end` are the occupied interval including any setup and cleanup
/// buffers, so two claims that merely touch at their displayed times still
/// conflict when their buffers overlap.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerClaim {
    pub id: String,
    /// The pool member resource (exact time) or the window (arrival) this
    /// claim occupies.
    pub supply_id: String,
    pub kind: LedgerKind,
    /// The authenticated channel the claim was allocated in, when the supply
    /// carries channel subquotas.
    pub channel: Option<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Recipient units consumed. Exact-time claims on one member consume one.
    pub units: u32,
    /// The duplicate-active key this claim holds, when the offering defines
    /// one.
    pub duplicate_key: Option<String>,
    /// Hold expiry. An expired hold stops consuming capacity at this instant
    /// even when the cleanup worker is delayed.
    pub expires_at: Option<DateTime<Utc>>,
}

/// The authoritative supply ledger at one observed instant, holding exactly
/// the claims that consume capacity now.
///
/// The store is expected to have filtered released, cancelled, and consumed
/// claims before building a snapshot; the evaluator still re-checks hold
/// expiry against `now` so a delayed cleanup worker can never keep an expired
/// hold alive.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerSnapshot {
    pub claims: Vec<LedgerClaim>,
}

impl LedgerSnapshot {
    /// The claims that consume capacity at `now`.
    pub fn consuming<'a>(
        &'a self,
        now: DateTime<Utc>,
    ) -> impl Iterator<Item = &'a LedgerClaim> + 'a {
        self.claims
            .iter()
            .filter(move |claim| claim.consumes_at(now))
    }

    /// Whether any consuming claim occupies `supply_id` in the half-open
    /// interval `[start, end)`, ignoring `exclude`.
    pub fn supply_occupied(
        &self,
        supply_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        exclude: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        self.consuming(now).any(|claim| {
            claim.supply_id == supply_id
                && Some(claim.id.as_str()) != exclude
                && claim.start < end
                && start < claim.end
        })
    }

    /// Recipient units consuming a window's supply at `now`, all channels or
    /// one channel only, ignoring `exclude`.
    pub fn window_units_allocated(
        &self,
        window_id: &str,
        channel: Option<&str>,
        exclude: Option<&str>,
        now: DateTime<Utc>,
    ) -> u32 {
        self.consuming(now)
            .filter(|claim| {
                claim.supply_id == window_id
                    && Some(claim.id.as_str()) != exclude
                    && channel.is_none_or(|wanted| claim.channel == Some(wanted.to_owned()))
            })
            .map(|claim| claim.units)
            // A snapshot past u32 units is already broken; saturating keeps
            // every later admission refused instead of wrapping toward zero
            // and re-admitting capacity no window holds.
            .fold(0, u32::saturating_add)
    }

    /// Whether a consuming claim already holds `duplicate_key` at `now`,
    /// ignoring `exclude`.
    pub fn duplicate_active(
        &self,
        duplicate_key: &str,
        exclude: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        self.consuming(now).any(|claim| {
            claim.duplicate_key.as_deref() == Some(duplicate_key)
                && Some(claim.id.as_str()) != exclude
        })
    }
}

impl LedgerClaim {
    /// A confirmed booking always consumes; a hold consumes only until it
    /// expires.
    pub fn consumes_at(&self, now: DateTime<Utc>) -> bool {
        match self.kind {
            LedgerKind::Booking => true,
            LedgerKind::Hold => self.expires_at.is_some_and(|expiry| expiry > now),
        }
    }
}

/// A location record: the layer of configuration an operator maintains at
/// runtime, not inside the authored policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationRecord {
    pub id: String,
    /// A named IANA timezone such as `Asia/Bangkok`.
    pub timezone: String,
}

/// One interchangeable member of a resource pool.
///
/// `available` carries no reason. Why a member is unavailable is private staff
/// information; the public answer to a caller is that capacity is exhausted.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PoolMember {
    pub resource_id: String,
    pub capabilities: Vec<String>,
    pub available: bool,
}

/// A pool of interchangeable resources backing exact-time offerings. A pool is
/// its concrete members, never an independent counter.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourcePool {
    pub id: String,
    pub members: Vec<PoolMember>,
}

/// An owned dated exception over local wall-clock time, the record form of
/// `registry_platform_calendar::CalendarException`. An exception is scoped to
/// one location: a closure at one counter never closes another.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarExceptionRecord {
    pub id: String,
    /// The location this exception applies to.
    pub location: String,
    pub kind: ExceptionRecordKind,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub reopens: Option<String>,
    pub authority: Option<String>,
}

/// The layer an exception occupies, mirrored for records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExceptionRecordKind {
    Closure,
    Opening,
}

impl CalendarExceptionRecord {
    /// Borrow this record for calendar expansion.
    pub fn borrowed(&self) -> CalendarException<'_> {
        CalendarException {
            id: &self.id,
            kind: match self.kind {
                ExceptionRecordKind::Closure => CalendarExceptionKind::Closure,
                ExceptionRecordKind::Opening => CalendarExceptionKind::Opening,
            },
            date: &self.date,
            start_time: &self.start_time,
            end_time: &self.end_time,
            reopens: self.reopens.as_deref(),
            authority: self.authority.as_deref(),
        }
    }
}

/// The environment records an admission runs against: locations, pools, and
/// dated exceptions. In production these are runtime records; in an offline
/// replay they are fixture facts. The evaluator never reads or mutates them
/// directly; its caller resolves them into the context the evaluator takes.
/// A fixture may omit an empty collection; replay fails fast when a case
/// references a record the facts do not carry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingFacts {
    #[serde(default)]
    pub locations: Vec<LocationRecord>,
    #[serde(default)]
    pub pools: Vec<ResourcePool>,
    #[serde(default)]
    pub exceptions: Vec<CalendarExceptionRecord>,
}

impl SchedulingFacts {
    #[must_use]
    pub fn location(&self, id: &str) -> Option<&LocationRecord> {
        self.locations.iter().find(|location| location.id == id)
    }

    #[must_use]
    pub fn pool(&self, id: &str) -> Option<&ResourcePool> {
        self.pools.iter().find(|pool| pool.id == id)
    }
}

/// A request for one admission decision. The evaluator is pure: it resolves
/// nothing, fetches nothing, and reads exactly what it is handed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionRequest {
    pub offering: String,
    pub start: DateTime<Utc>,
    pub party: PartyCounts,
    /// The authenticated channel, when the deployment allocates supply
    /// through channel subquotas.
    pub channel: Option<String>,
    /// The duplicate-active key, derived the same way the offering's policy
    /// prescribes.
    pub duplicate_key: Option<String>,
    /// The policy revision the caller resolved the offering under.
    pub policy_revision: u64,
    /// The window revision the caller resolved an arrival window under.
    pub window_revision: Option<u64>,
    /// The party's held capability references, matched against the offering's
    /// requirements.
    pub capabilities: Vec<String>,
    /// The party's held prerequisite references, matched against the
    /// offering's requirements.
    pub prerequisites: Vec<String>,
    /// The claim a reschedule replaces. Its allocation is excluded from the
    /// conflict checks for this request so a reschedule never competes with
    /// the appointment it replaces.
    pub reschedule_of: Option<String>,
}

/// The idempotent hash of an admission request.
///
/// The tuple is fixed in code, in this order, so a field reorder elsewhere can
/// never change a stored hash. The same request always hashes identically;
/// the same idempotency key with a different payload hashes differently, which
/// is exactly the distinction a retry must be able to make.
#[must_use]
pub fn admission_request_hash(request: &AdmissionRequest) -> String {
    let fixed = (
        &request.offering,
        request.start.to_rfc3339(),
        request.party.recipients,
        request.party.attendees,
        &request.channel,
        &request.duplicate_key,
        request.policy_revision,
        request.window_revision,
        &request.capabilities,
        &request.prerequisites,
        &request.reschedule_of,
    );
    let value = serde_json::to_value(&fixed).expect("the fixed tuple always serializes");
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .expect("the fixed tuple always canonicalizes");
    let digest = Sha256::digest(&canonical);
    format!("sha256:{}", hex(&digest))
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn utc(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 5, hour, minute, 0).unwrap()
    }

    fn request() -> AdmissionRequest {
        AdmissionRequest {
            offering: "registry-update-30".to_owned(),
            start: utc(2, 0),
            party: PartyCounts {
                recipients: 1,
                attendees: 1,
            },
            channel: Some("public".to_owned()),
            duplicate_key: Some("subject:one".to_owned()),
            policy_revision: 4,
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
            reschedule_of: None,
        }
    }

    #[test]
    fn a_confirmed_booking_consumes_but_an_expired_hold_does_not() {
        let now = utc(4, 0);
        let booking = LedgerClaim {
            id: "claim-1".to_owned(),
            supply_id: "station-1".to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start: utc(2, 0),
            end: utc(3, 0),
            units: 1,
            duplicate_key: None,
            expires_at: None,
        };
        let live_hold = LedgerClaim {
            id: "claim-2".to_owned(),
            supply_id: "station-2".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(2, 0),
            end: utc(3, 0),
            units: 1,
            duplicate_key: None,
            expires_at: Some(utc(4, 30)),
        };
        let expired_hold = LedgerClaim {
            id: "claim-3".to_owned(),
            supply_id: "station-3".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(2, 0),
            end: utc(3, 0),
            units: 1,
            duplicate_key: None,
            expires_at: Some(now),
        };
        let snapshot = LedgerSnapshot {
            claims: vec![booking, live_hold.clone(), expired_hold],
        };

        let consuming: Vec<&str> = snapshot
            .consuming(now)
            .map(|claim| claim.id.as_str())
            .collect();
        assert_eq!(consuming, vec!["claim-1", "claim-2"]);

        // A hold that expires exactly at `now` is already expired: expiry is
        // exclusive, so the caller can never observe a hold that died while
        // being evaluated.
        assert!(!live_hold.consumes_at(live_hold.expires_at.unwrap()));
    }

    #[test]
    fn supply_occupancy_is_half_open_and_honors_the_excluded_claim() {
        let now = utc(4, 0);
        let claim = LedgerClaim {
            id: "claim-1".to_owned(),
            supply_id: "station-1".to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start: utc(2, 0),
            end: utc(3, 0),
            units: 1,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = LedgerSnapshot {
            claims: vec![claim],
        };

        assert!(snapshot.supply_occupied("station-1", utc(1, 30), utc(2, 30), None, now));
        // Touching at an endpoint is not overlapping: [3:00, 3:30) starts
        // exactly where the claim ends.
        assert!(!snapshot.supply_occupied("station-1", utc(3, 0), utc(3, 30), None, now));
        assert!(!snapshot.supply_occupied("station-2", utc(2, 0), utc(3, 0), None, now));
        // A reschedule excludes its own allocation.
        assert!(!snapshot.supply_occupied("station-1", utc(2, 0), utc(3, 0), Some("claim-1"), now));
    }

    #[test]
    fn window_allocation_sums_per_channel_or_overall() {
        let now = utc(4, 0);
        let claim = |id: &str, channel: Option<&str>, units: u32| LedgerClaim {
            id: id.to_owned(),
            supply_id: "morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: channel.map(str::to_owned),
            start: utc(1, 0),
            end: utc(4, 0),
            units,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = LedgerSnapshot {
            claims: vec![
                claim("claim-1", Some("public"), 2),
                claim("claim-2", Some("assisted"), 1),
            ],
        };

        assert_eq!(
            snapshot.window_units_allocated("morning-window", None, None, now),
            3
        );
        assert_eq!(
            snapshot.window_units_allocated("morning-window", Some("public"), None, now),
            2
        );
        assert_eq!(
            snapshot.window_units_allocated("morning-window", Some("walk-in"), None, now),
            0
        );
        assert_eq!(
            snapshot.window_units_allocated("morning-window", None, Some("claim-2"), now),
            2
        );
    }

    #[test]
    fn window_allocation_saturates_instead_of_wrapping_past_u32() {
        let now = utc(4, 0);
        let claim = |id: &str, units: u32| LedgerClaim {
            id: id.to_owned(),
            supply_id: "morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start: utc(1, 0),
            end: utc(4, 0),
            units,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = LedgerSnapshot {
            claims: vec![claim("claim-1", u32::MAX), claim("claim-2", 1)],
        };
        // The saturated total keeps refusing; a wrapped one would read as 0
        // and hand the window its whole capacity back.
        assert_eq!(
            snapshot.window_units_allocated("morning-window", None, None, now),
            u32::MAX
        );
    }

    #[test]
    fn duplicate_keys_are_detected_only_on_consuming_claims() {
        let now = utc(4, 0);
        let expired_hold = LedgerClaim {
            id: "claim-1".to_owned(),
            supply_id: "morning-window".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(1, 0),
            end: utc(4, 0),
            units: 1,
            duplicate_key: Some("subject:one".to_owned()),
            expires_at: Some(utc(3, 0)),
        };
        let snapshot = LedgerSnapshot {
            claims: vec![expired_hold],
        };
        assert!(!snapshot.duplicate_active("subject:one", None, now));
    }

    #[test]
    fn the_same_request_always_hashes_identically() {
        assert_eq!(
            admission_request_hash(&request()),
            admission_request_hash(&request())
        );
        assert!(admission_request_hash(&request()).starts_with("sha256:"));
        assert_eq!(
            admission_request_hash(&request()).len(),
            "sha256:".len() + 64
        );
    }

    /// AT-06, pure half: a changed payload under the same caller-visible key
    /// must hash differently, or a retry could silently return the wrong
    /// appointment.
    #[test]
    fn a_changed_payload_hashes_differently() {
        let base = admission_request_hash(&request());

        let moved_start = AdmissionRequest {
            start: utc(2, 30),
            ..request()
        };
        assert_ne!(base, admission_request_hash(&moved_start));

        let grew_party = AdmissionRequest {
            party: PartyCounts {
                recipients: 2,
                attendees: 3,
            },
            ..request()
        };
        assert_ne!(base, admission_request_hash(&grew_party));

        let other_offering = AdmissionRequest {
            offering: "registry-update-45".to_owned(),
            ..request()
        };
        assert_ne!(base, admission_request_hash(&other_offering));

        let rescheduling = AdmissionRequest {
            reschedule_of: Some("claim-9".to_owned()),
            ..request()
        };
        assert_ne!(base, admission_request_hash(&rescheduling));
    }

    #[test]
    fn exception_records_borrow_into_calendar_expansion_form() {
        let record = CalendarExceptionRecord {
            id: "staff-meeting".to_owned(),
            location: "north-counter".to_owned(),
            kind: ExceptionRecordKind::Closure,
            date: "2026-10-05".to_owned(),
            start_time: "09:00".to_owned(),
            end_time: "10:00".to_owned(),
            reopens: None,
            authority: None,
        };
        let borrowed = record.borrowed();
        assert_eq!(borrowed.id, "staff-meeting");
        assert_eq!(borrowed.kind, CalendarExceptionKind::Closure);
        assert_eq!(borrowed.date, "2026-10-05");
    }

    #[test]
    fn lifecycle_enums_round_trip_and_refuse_unknown_states() {
        let hold: HoldState = serde_norway::from_str("active").unwrap();
        assert_eq!(hold, HoldState::Active);
        assert!(serde_norway::from_str::<HoldState>("parked").is_err());

        let attendance: AttendanceState = serde_norway::from_str("leftWithoutService").unwrap();
        assert_eq!(attendance, AttendanceState::LeftWithoutService);
        assert!(serde_norway::from_str::<AttendanceState>("no-show").is_err());

        let booking: BookingState = serde_norway::from_str("confirmed").unwrap();
        assert_eq!(booking, BookingState::Confirmed);
    }

    #[test]
    fn ledger_and_request_shapes_refuse_unknown_fields() {
        let claim_yaml = "id: claim-1\nsupplyId: station-1\nkind: booking\n\
                          start: 2026-10-05T02:00:00Z\nend: 2026-10-05T03:00:00Z\nunits: 1\n";
        assert!(serde_norway::from_str::<LedgerClaim>(claim_yaml).is_ok());
        assert!(
            serde_norway::from_str::<LedgerClaim>(&format!("{claim_yaml}note: stray\n")).is_err()
        );

        assert!(serde_norway::from_str::<PartyCounts>("recipients: 1\nattendees: 2\n").is_ok());
        assert!(serde_norway::from_str::<PartyCounts>("recipients: 1\n").is_err());
    }
}
