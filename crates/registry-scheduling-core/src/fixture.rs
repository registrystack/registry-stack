// SPDX-License-Identifier: Apache-2.0

//! Offline replay fixtures and the replay itself.
//!
//! A fixture is synthetic facts, a starting ledger, and an ordered list of
//! cases with their expected outcomes. Replay runs the same pure evaluators
//! the runtime runs, entirely offline: no network, no database, no clock. An
//! admitted case joins the ledger the later cases run against, and an
//! admitted reschedule replaces the allocation it names exactly once, so a
//! fixture can tell the story of several callers in sequence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use registry_platform_calendar::CalendarEvaluationError;

use crate::admission::{
    evaluate_exact_time_admission, evaluate_window_admission, ExactTimeContext, WindowContext,
};
use crate::model::{
    AdmissionRequest, LedgerClaim, LedgerKind, LedgerSnapshot, PartyCounts, SchedulingFacts,
};
use crate::naming::{SCHEDULING_FIXTURE_API_VERSION, SCHEDULING_FIXTURE_KIND};
use crate::policy::{SchedulingMode, SchedulingPolicy};
use crate::problem::ProblemCode;
use crate::resolve::{
    covers_span, location_closure_intervals, location_open_intervals, ResolveError,
};

/// One case's expected outcome.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase", deny_unknown_fields)]
pub enum FixtureExpectation {
    Admitted {
        units: u32,
        #[serde(default)]
        resource: Option<String>,
    },
    Refused {
        /// A public problem code, exactly as a caller would receive it.
        code: String,
    },
}

/// One replayed request as an author writes it.
///
/// This is the authoring form of an admission request, not the wire form. It
/// carries everything the wire request carries plus `rescheduleOf`, the claim
/// this case replaces: a fixture legitimately says "this case reschedules that
/// one", where an HTTP caller may not, because on the wire the exclusion is
/// the runtime's to supply from inside its own transaction.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureAdmissionRequest {
    pub offering: String,
    pub start: DateTime<Utc>,
    pub party: PartyCounts,
    pub channel: Option<String>,
    pub duplicate_key: Option<String>,
    pub policy_revision: u64,
    pub window_revision: Option<u64>,
    pub capabilities: Vec<String>,
    pub prerequisites: Vec<String>,
    /// The claim this case replaces. Its allocation is left out of this
    /// case's conflict checks and removed when the case is admitted, so a
    /// reschedule never competes with what it replaces.
    pub reschedule_of: Option<String>,
}

impl FixtureAdmissionRequest {
    /// The wire request this authored case makes, without the exclusion:
    /// that travels beside it, as the evaluator's own argument.
    ///
    /// Both sides are written out in full on purpose. Adding a field to
    /// either shape stops compiling here until the author decides what the
    /// other shape does with it.
    #[must_use]
    pub fn admission(&self) -> AdmissionRequest {
        let Self {
            offering,
            start,
            party,
            channel,
            duplicate_key,
            policy_revision,
            window_revision,
            capabilities,
            prerequisites,
            reschedule_of: _,
        } = self;
        AdmissionRequest {
            offering: offering.clone(),
            start: *start,
            party: *party,
            channel: channel.clone(),
            duplicate_key: duplicate_key.clone(),
            policy_revision: *policy_revision,
            window_revision: *window_revision,
            capabilities: capabilities.clone(),
            prerequisites: prerequisites.clone(),
        }
    }
}

/// One replayed request and its expectation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureCase {
    pub name: String,
    pub request: FixtureAdmissionRequest,
    pub expect: FixtureExpectation,
}

/// An offline replay fixture: synthetic facts, a starting ledger, and cases.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingFixture {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    /// The single observed instant every case runs at.
    pub now: DateTime<Utc>,
    pub facts: SchedulingFacts,
    #[serde(default)]
    pub initial: Vec<LedgerClaim>,
    pub cases: Vec<FixtureCase>,
}

/// Parse a fixture from its authored YAML, with the failing path preserved.
pub fn parse_fixture_yaml(
    text: &str,
) -> Result<SchedulingFixture, serde_path_to_error::Error<serde_norway::Error>> {
    let deserializer = serde_norway::Deserializer::from_str(text);
    serde_path_to_error::deserialize(deserializer)
}

/// Whether one replayed case matched its expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseStatus {
    Pass,
    Fail,
}

impl CaseStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// The outcome of one replayed case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseOutcome {
    pub name: String,
    pub status: CaseStatus,
    pub detail: Option<String>,
}

/// Replay stopped before a case could be evaluated: the fixture and policy do
/// not fit together, or an expectation names a code outside the closed
/// vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayError {
    #[error("the fixture envelope is not a scheduling fixture")]
    UnsupportedEnvelope,
    #[error("case {case} requests unknown offering {offering}")]
    UnknownOffering { case: String, offering: String },
    #[error("case {case} needs pool {pool}, which the facts do not declare")]
    UnknownPool { case: String, pool: String },
    #[error("case {case} needs pool {pool}, which has no members")]
    EmptyPool { case: String, pool: String },
    #[error("case {case} needs location {location}, which the facts do not declare")]
    UnknownLocation { case: String, location: String },
    #[error("case {case} needs window {window}, which the facts do not declare")]
    UnknownWindow { case: String, window: String },
    #[error("case name {case} is used more than once; case names identify claims")]
    DuplicateCaseName { case: String },
    #[error("case {case} reschedules claim {claim}, which no claim in the ledger carries")]
    UnknownRescheduleTarget { case: String, claim: String },
    #[error("case {case} expects code {code}, which is outside the closed vocabulary")]
    UnknownExpectationCode { case: String, code: String },
    #[error(
        "case {case} expects code {code}, which only the authorized explain path discloses; \
         expect the public code instead"
    )]
    DetailedExpectationCode { case: String, code: String },
    #[error(
        "case {case} targets offering {offering}, whose mode block is absent; the policy does \
         not pass its check"
    )]
    ModeBlockMissing { case: String, offering: String },
    #[error(
        "opening {opening} names holiday set {holiday_set}, which the policy does not declare"
    )]
    HolidaySetMissing {
        opening: String,
        holiday_set: String,
    },
    #[error("window {window} does not sit inside the location's published openings")]
    WindowOutsideOpenings { window: String },
    #[error("the calendar refused the configuration: {0}")]
    Calendar(#[from] CalendarEvaluationError),
}

impl SchedulingFixture {
    /// Check the fixture envelope and every expectation code before any case
    /// runs, so a broken fixture fails fast instead of half-way through.
    pub fn check(&self, policy: &SchedulingPolicy) -> Result<(), ReplayError> {
        if self.api_version != SCHEDULING_FIXTURE_API_VERSION
            || self.kind != SCHEDULING_FIXTURE_KIND
        {
            return Err(ReplayError::UnsupportedEnvelope);
        }
        // A replayed claim is identified by its case name, and a reschedule
        // names the claim it replaces. Two cases under one name would answer
        // to each other's id: the second silently erases the first's claim,
        // and one reschedule frees two allocations.
        let mut seen: Vec<&str> = Vec::with_capacity(self.cases.len());
        for case in &self.cases {
            if seen.contains(&case.name.as_str()) {
                return Err(ReplayError::DuplicateCaseName {
                    case: case.name.clone(),
                });
            }
            seen.push(&case.name);
        }
        for case in &self.cases {
            if let FixtureExpectation::Refused { code } = &case.expect {
                match ProblemCode::from_code(code) {
                    None => {
                        return Err(ReplayError::UnknownExpectationCode {
                            case: case.name.clone(),
                            code: code.clone(),
                        });
                    }
                    Some(problem) if problem.is_detailed_only() => {
                        return Err(ReplayError::DetailedExpectationCode {
                            case: case.name.clone(),
                            code: code.clone(),
                        });
                    }
                    Some(_) => {}
                }
            }
            let offering = policy.offering(&case.request.offering).ok_or_else(|| {
                ReplayError::UnknownOffering {
                    case: case.name.clone(),
                    offering: case.request.offering.clone(),
                }
            })?;
            let location = &offering.location;
            if self.facts.location(location).is_none() {
                return Err(ReplayError::UnknownLocation {
                    case: case.name.clone(),
                    location: location.clone(),
                });
            }
            match offering.mode {
                SchedulingMode::ExactTime => {
                    // The mode block is a policy check finding, not something
                    // the fixture harness may assume away: a policy that does
                    // not pass its check stops here instead of panicking.
                    let Some(exact) = offering.exact_time.as_ref() else {
                        return Err(ReplayError::ModeBlockMissing {
                            case: case.name.clone(),
                            offering: offering.id.clone(),
                        });
                    };
                    let pool_id = exact.pool.clone();
                    let pool =
                        self.facts
                            .pool(&pool_id)
                            .ok_or_else(|| ReplayError::UnknownPool {
                                case: case.name.clone(),
                                pool: pool_id.clone(),
                            })?;
                    if pool.members.is_empty() {
                        return Err(ReplayError::EmptyPool {
                            case: case.name.clone(),
                            pool: pool_id,
                        });
                    }
                }
                SchedulingMode::ArrivalWindow => {
                    let Some(arrival) = offering.arrival.as_ref() else {
                        return Err(ReplayError::ModeBlockMissing {
                            case: case.name.clone(),
                            offering: offering.id.clone(),
                        });
                    };
                    let window_id = arrival.window.clone();
                    let Some(window) = self.facts.window(&window_id) else {
                        return Err(ReplayError::UnknownWindow {
                            case: case.name.clone(),
                            window: window_id,
                        });
                    };
                    // The window must sit inside the location's published
                    // openings; a window floating outside every opening is a
                    // fixture telling a story the schedule never publishes.
                    let timezone = self
                        .facts
                        .location(&offering.location)
                        .expect("the location was resolved above")
                        .timezone
                        .clone();
                    // Structural validation uses the authored schedule before
                    // dated exceptions. A closure is a valid fixture fact
                    // whose case must reach admission and refuse as
                    // `location.closed`, not an invalid fixture definition.
                    let open = location_open_intervals(policy, &offering.location, &timezone, &[])?;
                    if !covers_span(&open, window.start, window.end) {
                        return Err(ReplayError::WindowOutsideOpenings { window: window_id });
                    }
                }
            }
        }
        Ok(())
    }

    /// Replay the cases in order against the policy, entirely offline.
    ///
    /// Every case runs at the fixture's fixed `now` through the same pure
    /// evaluators the runtime calls. An admitted case is recorded into the
    /// ledger as a confirmed booking; an admitted reschedule removes the
    /// allocation it replaces, exactly once. A refused case consumes nothing.
    pub fn replay(&self, policy: &SchedulingPolicy) -> Result<Vec<CaseOutcome>, ReplayError> {
        self.check(policy)?;
        let mut snapshot = LedgerSnapshot {
            claims: self.initial.clone(),
        };
        let mut outcomes = Vec::with_capacity(self.cases.len());
        for case in &self.cases {
            let outcome = match replay_case(policy, self, case, &mut snapshot) {
                Ok(admitted) => Ok(admitted),
                Err(CaseStoppage::Replay(error)) => return Err(error),
                Err(CaseStoppage::Refusal(refusal)) => Err(refusal),
            };
            let status = match (&case.expect, &outcome) {
                (FixtureExpectation::Admitted { units, resource }, Ok(recorded)) => {
                    let units_match = recorded.units == *units;
                    let resource_match = match resource {
                        None => true,
                        Some(expected) => recorded.resource.as_deref() == Some(expected.as_str()),
                    };
                    if units_match && resource_match {
                        CaseStatus::Pass
                    } else {
                        CaseStatus::Fail
                    }
                }
                (FixtureExpectation::Refused { code }, Err(refusal)) => {
                    if refusal.public_code().code() == code.as_str() {
                        CaseStatus::Pass
                    } else {
                        CaseStatus::Fail
                    }
                }
                _ => CaseStatus::Fail,
            };
            let detail = match &outcome {
                Ok(admitted) => Some(format!(
                    "admitted onto {} for {} unit(s)",
                    admitted.resource.as_deref().unwrap_or("the window"),
                    admitted.units
                )),
                Err(refusal) => Some(format!(
                    "refused {} (detailed: {})",
                    refusal.public_code().code(),
                    refusal.detailed_code().code()
                )),
            };
            outcomes.push(CaseOutcome {
                name: case.name.clone(),
                status,
                detail,
            });
        }
        Ok(outcomes)
    }
}

/// What stopped one replayed case: a replay-level configuration problem, or
/// the admission refusal the evaluators returned.
#[derive(Debug)]
enum CaseStoppage {
    Replay(ReplayError),
    Refusal(crate::admission::AdmissionRefusal),
}

impl From<crate::admission::AdmissionRefusal> for CaseStoppage {
    fn from(refusal: crate::admission::AdmissionRefusal) -> Self {
        Self::Refusal(refusal)
    }
}

fn replay_case(
    policy: &SchedulingPolicy,
    fixture: &SchedulingFixture,
    case: &FixtureCase,
    snapshot: &mut LedgerSnapshot,
) -> Result<crate::admission::Admission, CaseStoppage> {
    let request = &case.request.admission();
    // A reschedule of a claim the ledger does not carry excludes nothing and
    // replaces nothing, so it would quietly replay as an ordinary booking and
    // pass against an expectation it never tested. It is an authoring error,
    // not a caller's refusal.
    let exclude = case.request.reschedule_of.as_deref();
    if let Some(target) = exclude {
        if !snapshot.claims.iter().any(|claim| claim.id == target) {
            return Err(CaseStoppage::Replay(ReplayError::UnknownRescheduleTarget {
                case: case.name.clone(),
                claim: target.to_owned(),
            }));
        }
    }

    let offering = policy
        .offering(&request.offering)
        .ok_or(CaseStoppage::Refusal(
            crate::admission::AdmissionRefusal::ScheduleUnpublished,
        ))?;
    let location = fixture
        .facts
        .location(&offering.location)
        .ok_or(CaseStoppage::Replay(ReplayError::UnknownLocation {
            case: case.name.clone(),
            location: offering.location.clone(),
        }))?;

    let revision = policy.scheduling.version;
    match offering.mode {
        SchedulingMode::ExactTime => {
            let exact = offering.exact_time.as_ref().ok_or(CaseStoppage::Replay(
                ReplayError::ModeBlockMissing {
                    case: case.name.clone(),
                    offering: offering.id.clone(),
                },
            ))?;
            let pool = fixture.facts.pool(&exact.pool).ok_or(CaseStoppage::Replay(
                ReplayError::UnknownPool {
                    case: case.name.clone(),
                    pool: exact.pool.clone(),
                },
            ))?;
            let exceptions: Vec<_> = fixture
                .facts
                .exceptions
                .iter()
                .filter(|exception| exception.location == offering.location)
                .map(|exception| exception.borrowed())
                .collect();
            let open = location_open_intervals(
                policy,
                &offering.location,
                &location.timezone,
                &exceptions,
            )
            .map_err(|error| CaseStoppage::Replay(error.into()))?;
            let closures =
                location_closure_intervals(&fixture.facts, &offering.location, &location.timezone)
                    .map_err(|error| CaseStoppage::Replay(error.into()))?;
            let context = ExactTimeContext {
                offering,
                exact,
                members: &pool.members,
                open: &open,
                closures: &closures,
                snapshot,
                policy_revision: revision,
                now: fixture.now,
            };
            let admitted = evaluate_exact_time_admission(&context, request, exclude)?;
            let supply = admitted
                .resource
                .clone()
                .expect("an exact-time admission names its member");
            record_admission(&case.name, &admitted, &supply, &case.request, snapshot);
            Ok(admitted)
        }
        SchedulingMode::ArrivalWindow => {
            let arrival = offering.arrival.as_ref().ok_or(CaseStoppage::Replay(
                ReplayError::ModeBlockMissing {
                    case: case.name.clone(),
                    offering: offering.id.clone(),
                },
            ))?;
            let window = fixture
                .facts
                .window(&arrival.window)
                .ok_or(CaseStoppage::Replay(ReplayError::UnknownWindow {
                    case: case.name.clone(),
                    window: arrival.window.clone(),
                }))?;
            let exceptions: Vec<_> = fixture
                .facts
                .exceptions
                .iter()
                .filter(|exception| exception.location == offering.location)
                .map(|exception| exception.borrowed())
                .collect();
            let open = location_open_intervals(
                policy,
                &offering.location,
                &location.timezone,
                &exceptions,
            )
            .map_err(|error| CaseStoppage::Replay(error.into()))?;
            let closures =
                location_closure_intervals(&fixture.facts, &offering.location, &location.timezone)
                    .map_err(|error| CaseStoppage::Replay(error.into()))?;
            let context = WindowContext {
                offering,
                window,
                open: &open,
                closures: &closures,
                lead_time_minutes: arrival.lead_time_minutes,
                horizon_days: arrival.horizon_days,
                snapshot,
                policy_revision: revision,
                channels: &policy.channels,
                now: fixture.now,
            };
            let admitted = evaluate_window_admission(&context, request, exclude)?;
            // A window claim occupies the window itself, so later cases sum
            // against the window's published units.
            record_admission(&case.name, &admitted, &window.id, &case.request, snapshot);
            Ok(admitted)
        }
    }
}

/// Record an admitted case into the replay ledger, replacing the allocation a
/// reschedule names exactly once. The recorded claim id is `case:` plus the
/// case name, so a later case can reschedule what an earlier case booked.
fn record_admission(
    case: &str,
    admitted: &crate::admission::Admission,
    supply_id: &str,
    request: &FixtureAdmissionRequest,
    snapshot: &mut LedgerSnapshot,
) {
    if let Some(replaced) = &request.reschedule_of {
        snapshot.claims.retain(|claim| &claim.id != replaced);
    }
    snapshot.claims.push(LedgerClaim {
        id: format!("case:{case}"),
        offering: request.offering.clone(),
        supply_id: supply_id.to_owned(),
        kind: LedgerKind::Booking,
        channel: request.channel.clone(),
        start: admitted.occupied_start,
        end: admitted.occupied_end,
        units: admitted.units,
        duplicate_key: request.duplicate_key.clone(),
        // A booking recorded by replay never expires; holds are exercised
        // through the evaluators directly.
        expires_at: None,
    });
}

impl From<ResolveError> for ReplayError {
    fn from(error: ResolveError) -> Self {
        match error {
            ResolveError::HolidaySetMissing {
                opening,
                holiday_set,
            } => Self::HolidaySetMissing {
                opening,
                holiday_set,
            },
            ResolveError::Calendar(error) => Self::Calendar(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CalendarExceptionRecord, ExceptionRecordKind, LocationRecord, PartyCounts};
    use registry_platform_calendar::CalendarInterval;

    fn exact_time_fixture_yaml() -> &'static str {
        r#"
apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: last-station
now: 2026-10-05T00:00:00Z
facts:
  locations:
    - id: north-counter
      timezone: Asia/Bangkok
  pools:
    - id: update-stations
      members:
        - resourceId: station-1
          capabilities: []
          available: true
        - resourceId: station-2
          capabilities: []
          available: true
initial: []
cases:
  - name: first-caller-takes-the-last-station
    request:
      offering: registry-update-30
      start: 2026-10-05T02:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:one
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
  - name: same-key-retry-is-refused
    request:
      offering: registry-update-30
      start: 2026-10-05T03:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:one
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: booking.duplicate-active
"#
    }

    fn policy_for_fixture() -> SchedulingPolicy {
        crate::policy::parse_policy_yaml(
            r#"
apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: registry-updates
  version: 1
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: north-counter
    because: A 30-minute update at an interchangeable station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 30
      pool: update-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    duplicateActiveKey: subject
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: []
openings:
  - id: counter-hours
    location: north-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-05"
    effectiveUntil: "2026-10-05"
    because: Counter opening hours reviewed by the office manager.
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#,
        )
        .expect("the policy parses")
    }

    #[test]
    fn fixtures_parse_and_refuse_unknown_fields() {
        let fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        assert_eq!(fixture.name, "last-station");
        assert!(
            parse_fixture_yaml(&format!("{}stray: true\n", exact_time_fixture_yaml())).is_err()
        );
    }

    #[test]
    fn replay_threads_admitted_cases_into_the_ledger() {
        let policy = policy_for_fixture();
        let fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        let outcomes = fixture.replay(&policy).expect("replays");
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].status, CaseStatus::Pass);
        assert_eq!(outcomes[1].status, CaseStatus::Pass);
        // The first case's duplicate key is live for the second.
        assert!(outcomes[1]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("booking.duplicate-active")));
    }

    #[test]
    fn an_admitted_reschedule_replaces_its_allocation_once() {
        let policy = policy_for_fixture();
        let yaml = r#"
apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: move-one-booking
now: 2026-10-05T00:00:00Z
facts:
  locations:
    - id: north-counter
      timezone: Asia/Bangkok
  pools:
    - id: update-stations
      members:
        - resourceId: station-1
          capabilities: []
          available: true
initial:
  - id: booking-9
    offering: registry-update-30
    supplyId: station-1
    kind: booking
    start: 2026-10-05T02:00:00Z
    end: 2026-10-05T02:30:00Z
    units: 1
    duplicateKey: subject:one
cases:
  - name: reschedule-excludes-and-replaces-its-own-allocation
    request:
      offering: registry-update-30
      start: 2026-10-05T02:30:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:one
      policyRevision: 1
      rescheduleOf: booking-9
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: station-1
  - name: the-freed-slot-serves-another-caller
    request:
      offering: registry-update-30
      start: 2026-10-05T02:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:two
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: station-1
"#;
        let fixture = parse_fixture_yaml(yaml).expect("parses");
        let outcomes = fixture.replay(&policy).expect("replays");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.status == CaseStatus::Pass));
    }

    /// COR-6. A replayed claim is identified by its case name, so two cases
    /// under one name answer to each other's id: the second erases the
    /// first's claim and one reschedule frees two allocations.
    #[test]
    fn duplicate_case_names_are_refused_before_any_case_runs() {
        let policy = policy_for_fixture();
        let mut fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        let repeated = fixture.cases[0].name.clone();
        fixture.cases[1].name = repeated.clone();
        assert_eq!(
            fixture.check(&policy),
            Err(ReplayError::DuplicateCaseName {
                case: repeated.clone()
            })
        );
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::DuplicateCaseName { case: repeated })
        );
    }

    /// COR-7. A reschedule naming a claim the ledger does not carry excludes
    /// nothing and replaces nothing, so it would replay as an ordinary
    /// booking and pass against an expectation it never tested.
    #[test]
    fn a_reschedule_of_a_claim_the_ledger_does_not_carry_is_reported() {
        let policy = policy_for_fixture();
        let mut fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        fixture.cases[0].request.reschedule_of = Some("booking-404".to_owned());
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::UnknownRescheduleTarget {
                case: fixture.cases[0].name.clone(),
                claim: "booking-404".to_owned(),
            })
        );
    }

    #[test]
    fn broken_fixtures_stop_before_running() {
        let policy = policy_for_fixture();
        let mut fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");

        fixture.cases[1].expect = FixtureExpectation::Refused {
            code: "authorization.refused".to_owned(),
        };
        assert_eq!(
            fixture.check(&policy),
            Err(ReplayError::UnknownExpectationCode {
                case: "same-key-retry-is-refused".to_owned(),
                code: "authorization.refused".to_owned()
            })
        );

        fixture.cases[1].expect = FixtureExpectation::Refused {
            code: "capacity.exhausted".to_owned(),
        };
        fixture.cases[0].request.offering = "no-such-offering".to_owned();
        assert!(matches!(
            fixture.check(&policy),
            Err(ReplayError::UnknownOffering { .. })
        ));
    }

    /// A detailed-only expectation code can never match: replay compares the
    /// public projection, so the check refuses it up front with the code named.
    #[test]
    fn a_detailed_only_expectation_code_is_refused_before_any_case_runs() {
        let policy = policy_for_fixture();
        let mut fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        fixture.cases[1].expect = FixtureExpectation::Refused {
            code: "resource.unavailable".to_owned(),
        };
        assert_eq!(
            fixture.check(&policy),
            Err(ReplayError::DetailedExpectationCode {
                case: "same-key-retry-is-refused".to_owned(),
                code: "resource.unavailable".to_owned(),
            })
        );
    }

    /// A policy whose mode block is missing fails the fixture with a typed
    /// error naming the case and the offering, never a panic: replay must not
    /// assume the policy passed a check it never ran.
    #[test]
    fn a_policy_missing_its_mode_block_fails_the_fixture_not_the_process() {
        let mut policy = policy_for_fixture();
        policy.offerings[0].exact_time = None;
        let fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        assert_eq!(
            fixture.check(&policy),
            Err(ReplayError::ModeBlockMissing {
                case: "first-caller-takes-the-last-station".to_owned(),
                offering: "registry-update-30".to_owned(),
            })
        );
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::ModeBlockMissing {
                case: "first-caller-takes-the-last-station".to_owned(),
                offering: "registry-update-30".to_owned(),
            })
        );
    }

    /// An opening referencing a holiday set the policy does not declare stops
    /// replay at the opening that carries it, through both the arrival-window
    /// check path and the exact-time expansion path.
    #[test]
    fn an_opening_referencing_an_undeclared_holiday_set_fails_the_fixture() {
        let mut policy = policy_for_fixture();
        policy.openings[0].holiday_set = "no-such-holidays".to_owned();
        let fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::HolidaySetMissing {
                opening: "counter-hours".to_owned(),
                holiday_set: "no-such-holidays".to_owned(),
            })
        );
    }

    #[test]
    fn closures_and_openings_come_from_the_facts_for_the_location() {
        let policy = policy_for_fixture();
        let exceptions: Vec<registry_platform_calendar::CalendarException<'_>> = Vec::new();
        let open = location_open_intervals(&policy, "north-counter", "Asia/Bangkok", &exceptions)
            .expect("expands");
        // 2026-10-05 is a Monday: one 09:00-12:30 Bangkok interval, and
        // 09:00 Bangkok is 02:00Z the same day.
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].start.to_rfc3339(), "2026-10-05T02:00:00+00:00");
        assert_eq!(open[0].end.to_rfc3339(), "2026-10-05T05:30:00+00:00");

        let facts = SchedulingFacts {
            locations: vec![LocationRecord {
                id: "north-counter".to_owned(),
                timezone: "Asia/Bangkok".to_owned(),
            }],
            pools: vec![],
            windows: vec![],
            exceptions: vec![crate::model::CalendarExceptionRecord {
                id: "systems-training".to_owned(),
                location: "north-counter".to_owned(),
                kind: crate::model::ExceptionRecordKind::Closure,
                date: "2026-10-05".to_owned(),
                start_time: "09:00".to_owned(),
                end_time: "10:00".to_owned(),
                reopens: None,
                authority: None,
            }],
        };
        let closures =
            location_closure_intervals(&facts, "north-counter", "Asia/Bangkok").expect("converts");
        assert_eq!(closures.len(), 1);
        assert_eq!(closures[0].start.to_rfc3339(), "2026-10-05T02:00:00+00:00");

        // An exception at another location never closes this one.
        let other =
            location_closure_intervals(&facts, "south-counter", "Asia/Bangkok").expect("converts");
        assert!(other.is_empty());
    }

    /// A window fixture threads admitted cases into the window's own supply,
    /// so the total and the channel subquota both deplete as callers arrive.
    #[test]
    fn window_cases_deplete_the_published_window() {
        let yaml = r#"
apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: household-morning
now: 2026-10-09T20:00:00Z
facts:
  locations:
    - id: civic-hall
      timezone: Asia/Bangkok
  pools: []
  windows:
    - id: household-morning-window
      revision: 2
      offering: household-morning
      location: civic-hall
      start: 2026-10-10T01:00:00Z
      end: 2026-10-10T03:00:00Z
      units: 3
      unitsPolicy:
        kind: perRecipient
        perRecipient: 1
        because: Each recipient consumes one serving slot.
      subquotas:
        - id: public-quota
          channel: public
          units: 2
          because: Most households book the public channel.
        - id: assisted-quota
          channel: assisted
          units: 1
          because: Assisted bookings hold a protected unit.
      because: The Saturday morning household block.
initial: []
cases:
  - name: first-household
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 2
        attendees: 3
      channel: public
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 2
  - name: second-household-overdraws-the-public-subquota
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: public
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: capacity.exhausted
  - name: assisted-household-fits-the-protected-unit
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: assisted
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
"#;
        let policy = crate::policy::parse_policy_yaml(
            r#"
apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: household-days
  version: 3
services:
  - id: household-day
    label: Household registration day
offerings:
  - id: household-morning
    service: household-day
    label: Morning household block
    mode: arrival-window
    location: civic-hall
    because: Households arrive in a served morning block.
    arrival:
      window: household-morning-window
      leadTimeMinutes: 60
      horizonDays: 45
    cancellationCutoffMinutes: 1440
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: []
openings:
  - id: hall-hours
    location: civic-hall
    holidaySet: office-holidays
    weekdays: [sat]
    startTime: "08:00"
    endTime: "12:00"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: The hall opens on Saturday mornings.
holdPolicy:
  ttlMinutes: 10
  maxPerCaller: 2
  because: Households need a few minutes to gather documents.
"#,
        )
        .expect("the policy parses");
        assert!(policy.check().is_empty(), "{:?}", policy.check());

        let fixture = parse_fixture_yaml(yaml).expect("parses");
        let outcomes = fixture.replay(&policy).expect("replays");
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.status == CaseStatus::Pass),
            "{outcomes:?}"
        );

        let mut closed = parse_fixture_yaml(yaml).expect("parses a closed-window fixture");
        closed.facts.exceptions.push(CalendarExceptionRecord {
            id: "hall-closure".to_owned(),
            location: "civic-hall".to_owned(),
            kind: ExceptionRecordKind::Closure,
            date: "2026-10-10".to_owned(),
            start_time: "08:00".to_owned(),
            end_time: "12:00".to_owned(),
            reopens: None,
            authority: None,
        });
        closed.cases.truncate(1);
        closed.cases[0].expect = FixtureExpectation::Refused {
            code: "location.closed".to_owned(),
        };
        let outcomes = closed
            .replay(&policy)
            .expect("the closure reaches admission");
        assert_eq!(outcomes[0].status, CaseStatus::Pass, "{outcomes:?}");
    }

    #[test]
    fn party_counts_parse_from_the_fixture_surface() {
        let fixture = parse_fixture_yaml(exact_time_fixture_yaml()).expect("parses");
        assert_eq!(
            fixture.cases[0].request.party,
            PartyCounts {
                recipients: 1,
                attendees: 1,
            }
        );
    }

    #[test]
    fn span_coverage_requires_an_unbroken_union() {
        use chrono::TimeZone as _;
        let at =
            |hour: u32, minute: u32| Utc.with_ymd_and_hms(2026, 10, 10, hour, minute, 0).unwrap();
        let span = |sh: u32, sm: u32, eh: u32, em: u32| CalendarInterval {
            start: at(sh, sm),
            end: at(eh, em),
        };

        // Two touching halves cover the whole; a gap in the middle does not.
        assert!(covers_span(
            &[span(1, 0, 2, 0), span(2, 0, 3, 0)],
            at(1, 0),
            at(3, 0)
        ));
        assert!(!covers_span(
            &[span(1, 0, 2, 0), span(2, 30, 4, 0)],
            at(1, 0),
            at(3, 0)
        ));
        assert!(!covers_span(&[span(2, 0, 4, 0)], at(1, 0), at(3, 0)));
        assert!(!covers_span(&[], at(1, 0), at(3, 0)));
    }
}
