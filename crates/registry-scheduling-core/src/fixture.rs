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
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Invalid, Reader, RemovedKey, Report,
    RetiredApiVersion,
};
use serde::{de, Deserialize, Deserializer};

use registry_platform_calendar::CalendarEvaluationError;

use crate::admission::{
    evaluate_exact_time_admission, evaluate_window_admission, ExactTimeContext, WindowContext,
};
use crate::diagnostics::{findings_report, FindingArea, PolicyCheckReason, SchedulingDiagnostic};
use crate::model::{
    AdmissionRequest, LedgerClaim, LedgerKind, LedgerSnapshot, PartyCounts, SchedulingFacts,
};
use crate::naming::{
    RETIRED_SCHEDULING_FIXTURE_API_VERSION, SCHEDULING_FIXTURE_API_VERSION, SCHEDULING_FIXTURE_KIND,
};
use crate::policy::{SchedulingMode, SchedulingPolicy, MAXIMUM_COLLECTION_ENTRIES};
use crate::problem::ProblemCode;
use crate::resolve::{
    covers_span, location_closure_intervals, location_open_intervals, ResolveError,
};
use crate::typed::{MAXIMUM_REVISION, MAXIMUM_UNITS};

/// The policy revision replay runs every case under. A case resolves its
/// offering at this revision; a case naming another exercises the
/// `policy.changed` refusal.
pub const REPLAY_POLICY_REVISION: u64 = 1;

/// The format a replay fixture declares (CFG-ENV-1).
pub const SCHEDULING_FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: SCHEDULING_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(SCHEDULING_FIXTURE_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: RETIRED_SCHEDULING_FIXTURE_API_VERSION,
            replacement:
                "Write apiVersion: id.registrystack.org/formats/scheduling/fixture/v1alpha1, \
                          and type: admitted or type: refused in place of each outcome.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/cases/*/expect/outcome",
            replacement: "Write type: admitted or type: refused.",
        },
        RemovedKey {
            pointer: "/facts/windows/*/unitsPolicy/kind",
            replacement: "Write type: fixed, per-recipient, or banded-table.",
        },
        RemovedKey {
            pointer: "/facts/windows/*/unitsPolicy/aboveHighestBand/policy",
            replacement: "Write type: refuse or units.",
        },
    ],
};

/// One case's expected outcome, chosen by its `type` member.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum FixtureExpectation {
    Admitted {
        #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
        )]
        units: u32,
        /// The pool member an exact-time case lands on. Omit it to accept
        /// any member.
        #[serde(
            default,
            deserialize_with = "crate::typed::optional_local_id",
            skip_serializing_if = "Option::is_none"
        )]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "Option<registry_platform_yaml::LocalId>")
        )]
        resource: Option<String>,
    },
    Refused {
        /// A public problem code, exactly as a caller would receive it.
        #[serde(deserialize_with = "public_problem_code")]
        #[cfg_attr(
            feature = "schema",
            schemars(schema_with = "public_problem_code_schema")
        )]
        code: ProblemCode,
    },
}
registry_platform_yaml::tagged_union!(FixtureExpectation);

/// A code outside the closed problem vocabulary.
const UNKNOWN_PROBLEM_CODE: Invalid = Invalid::expected(
    "a problem code Registry Scheduling returns",
    "Write a code from the Scheduling problem vocabulary, such as capacity.exhausted.",
);

/// A code a caller never receives as the public projection of a refusal.
const DETAILED_PROBLEM_CODE: Invalid = Invalid::expected(
    "a public problem code",
    "Expect the public code a caller receives; the detailed code is disclosed only on the \
     authorized explain path.",
);

/// A refused case's expected code: public, from the closed vocabulary.
fn public_problem_code<'de, D>(deserializer: D) -> Result<ProblemCode, D::Error>
where
    D: Deserializer<'de>,
{
    let code = String::deserialize(deserializer)?;
    match ProblemCode::from_code(&code) {
        None => Err(de::Error::custom(UNKNOWN_PROBLEM_CODE)),
        Some(problem) if problem.is_detailed_only() => {
            Err(de::Error::custom(DETAILED_PROBLEM_CODE))
        }
        Some(problem) => Ok(problem),
    }
}

#[cfg(feature = "schema")]
fn public_problem_code_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let codes: Vec<&str> = ProblemCode::ALL
        .iter()
        .filter(|problem| !problem.is_detailed_only())
        .map(|problem| problem.code())
        .collect();
    schemars::json_schema!({ "type": "string", "enum": codes })
}

/// The party one replayed case requests for. Zero is allowed in both counts
/// so a fixture can exercise the refusal of a party the offering cannot
/// serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureParty {
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 0, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MAXIMUM_UNITS>")
    )]
    pub recipients: u32,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 0, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MAXIMUM_UNITS>")
    )]
    pub attendees: u32,
}

/// One replayed request as an author writes it.
///
/// This is the authoring form of an admission request, not the wire form. It
/// carries everything the wire request carries plus `rescheduleOf`, the claim
/// this case replaces: a fixture legitimately says "this case reschedules that
/// one", where an HTTP caller may not, because on the wire the exclusion is
/// the runtime's to supply from inside its own transaction.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureAdmissionRequest {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub offering: String,
    pub start: DateTime<Utc>,
    pub party: FixtureParty,
    /// The channel the caller books through. It is free text so a fixture
    /// can exercise the refusal of a channel outside the vocabulary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_key: Option<String>,
    /// The policy revision the caller resolved the offering under. Replay
    /// runs the policy at revision 1.
    #[serde(deserialize_with = "crate::typed::bounded_u64::<_, 1, MAXIMUM_REVISION>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, MAXIMUM_REVISION>")
    )]
    pub policy_revision: u64,
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_bounded_u64::<_, 1, MAXIMUM_REVISION>",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::BoundedU64<1, MAXIMUM_REVISION>>")
    )]
    pub window_revision: Option<u64>,
    /// The capabilities the party holds. A party holding none omits the
    /// member.
    #[serde(
        default,
        deserialize_with = "crate::typed::unique_local_ids",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>",
            length(max = 256)
        )
    )]
    pub capabilities: Vec<String>,
    /// The prerequisites the party holds. A party holding none omits the
    /// member.
    #[serde(
        default,
        deserialize_with = "crate::typed::unique_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<String>", length(max = 256))
    )]
    pub prerequisites: Vec<String>,
    /// The claim this case replaces. Its allocation is left out of this
    /// case's conflict checks and removed when the case is admitted, so a
    /// reschedule never competes with what it replaces. A claim an earlier
    /// case booked is `case:` followed by that case's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            party: PartyCounts {
                recipients: party.recipients,
                attendees: party.attendees,
            },
            channel: channel.clone(),
            duplicate_key: duplicate_key.clone(),
            policy_revision: *policy_revision,
            window_revision: *window_revision,
            capabilities: capabilities.clone(),
            prerequisites: prerequisites.clone(),
            external_references: Vec::new(),
        }
    }
}

/// One replayed request and its expectation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureCase {
    /// The case name, which also identifies the claim an admitted case
    /// records.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub name: String,
    pub request: FixtureAdmissionRequest,
    pub expect: FixtureExpectation,
}

/// An offline replay fixture: synthetic facts, a starting ledger, and cases.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingFixture {
    #[cfg_attr(
        feature = "schema",
        schemars(extend("const" = "id.registrystack.org/formats/scheduling/fixture/v1alpha1"))
    )]
    pub api_version: String,
    #[cfg_attr(feature = "schema", schemars(extend("const" = "SchedulingFixture")))]
    pub kind: String,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub name: String,
    /// The single observed instant every case runs at.
    pub now: DateTime<Utc>,
    pub facts: SchedulingFacts,
    /// The claims the ledger holds before the first case. A fixture that
    /// starts from an empty ledger omits the member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub initial: Vec<LedgerClaim>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub cases: Vec<FixtureCase>,
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
/// not fit together.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayError {
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
    #[error(
        "case {case} sets rescheduleOf to a claim identifier that no claim in the ledger carries"
    )]
    UnknownRescheduleTarget { case: String },
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

/// The name a fixture read from bytes carries in its diagnostics when the
/// caller has no file name for it.
pub const SCHEDULING_FIXTURE_FILE: &str = "fixture.yaml";

impl SchedulingFixture {
    /// Read one fixture document, refusing what its shape does not carry
    /// with every position.
    pub fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = registry_platform_config::AuthoredExpressions;
        Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&SCHEDULING_FIXTURE_FORMAT))
    }

    /// Read one fixture and check it against `policy`: every structural
    /// problem, or every finding of [`SchedulingFixture::findings`], each at
    /// its position.
    pub fn read(
        file: &str,
        bytes: &[u8],
        policy: &SchedulingPolicy,
    ) -> Result<Decoded<Self>, Report> {
        let decoded = Self::decode(file, bytes)?;
        let findings = decoded.value.findings(policy);
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(findings_report(&decoded.document, &findings))
        }
    }

    /// What a check can say about this fixture before any case runs: its
    /// case names identify claims and so stay distinct, its collections stay
    /// within their bounds, every case names an offering `policy` declares,
    /// and its facts are records `policy` accepts. An offering whose window
    /// the facts do not carry is not a finding here: a fixture replays the
    /// offerings its cases name.
    #[must_use]
    pub fn findings(&self, policy: &SchedulingPolicy) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        let fixture = |path: String, reason| {
            SchedulingDiagnostic::in_area(FindingArea::Fixture, path, reason)
        };
        if self.cases.is_empty() {
            findings.push(fixture(
                "/cases".to_owned(),
                PolicyCheckReason::EmptyCollection,
            ));
        }
        if self.cases.len() > MAXIMUM_COLLECTION_ENTRIES {
            findings.push(fixture(
                "/cases".to_owned(),
                PolicyCheckReason::TooManyEntries,
            ));
        }
        if self.initial.len() > MAXIMUM_COLLECTION_ENTRIES {
            findings.push(fixture(
                "/initial".to_owned(),
                PolicyCheckReason::TooManyEntries,
            ));
        }
        // A replayed claim is identified by its case name, and a reschedule
        // names the claim it replaces. Two cases under one name would answer
        // to each other's id: the second silently erases the first's claim,
        // and one reschedule frees two allocations.
        for (index, case) in self.cases.iter().enumerate() {
            if self.cases[..index]
                .iter()
                .any(|earlier| earlier.name == case.name)
            {
                findings.push(fixture(
                    format!("/cases/{index}/name"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
        }
        // A case replays against an offering of the project, by identifier;
        // one the project does not declare would stop replay before any case
        // ran.
        for (index, case) in self.cases.iter().enumerate() {
            if policy.offering(&case.request.offering).is_none() {
                findings.push(fixture(
                    format!("/cases/{index}/request/offering"),
                    PolicyCheckReason::UnknownOffering,
                ));
            }
        }
        findings.extend(
            self.facts
                .check(policy)
                .into_iter()
                .filter(|finding| finding.area == FindingArea::Records)
                .map(|finding| finding.with_area(FindingArea::Fixture).under("/facts")),
        );
        findings
    }

    /// Check that every case fits the policy and the facts before any case
    /// runs, so a broken fixture fails fast instead of half-way through.
    pub fn check(&self, policy: &SchedulingPolicy) -> Result<(), ReplayError> {
        // A replayed claim is identified by its case name; see
        // `SchedulingFixture::findings`.
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
                    if refusal.public_code() == *code {
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

    let revision = REPLAY_POLICY_REVISION;
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
    use crate::model::{CalendarExceptionRecord, ExceptionRecordKind, LocationRecord};
    use crate::naming::AUTHORED_POLICY_FILE;
    use registry_platform_calendar::CalendarInterval;

    const EXACT_TIME_FIXTURE: &str = r#"
apiVersion: id.registrystack.org/formats/scheduling/fixture/v1alpha1
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
          available: true
        - resourceId: station-2
          available: true
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
    expect:
      type: admitted
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
    expect:
      type: refused
      code: booking.duplicate-active
"#;

    const EXACT_TIME_PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project:
  id: registry-updates
  version: "1"
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
      maximumRecipients: 1
    cancellationCutoffMinutes: 240
    duplicateActiveKey: subject
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
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
channels: [public]
holdPolicy:
  ttlMinutes: 5
  maximumPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

    fn read_policy(yaml: &str) -> SchedulingPolicy {
        SchedulingPolicy::read(AUTHORED_POLICY_FILE, yaml.as_bytes())
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value
    }

    fn policy_for_fixture() -> SchedulingPolicy {
        read_policy(EXACT_TIME_PROJECT)
    }

    fn read_fixture(yaml: &str, policy: &SchedulingPolicy) -> SchedulingFixture {
        SchedulingFixture::read(SCHEDULING_FIXTURE_FILE, yaml.as_bytes(), policy)
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value
    }

    /// The diagnostics a refused fixture reports, as `pointer code`.
    fn refusals(yaml: &str, policy: &SchedulingPolicy) -> Vec<String> {
        match SchedulingFixture::read(SCHEDULING_FIXTURE_FILE, yaml.as_bytes(), policy) {
            Ok(_) => Vec::new(),
            Err(report) => report
                .diagnostics()
                .iter()
                .map(|diagnostic| format!("{} {}", diagnostic.path, diagnostic.code))
                .collect(),
        }
    }

    #[test]
    fn fixtures_read_and_refuse_unknown_fields() {
        let policy = policy_for_fixture();
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        assert_eq!(fixture.name, "last-station");
        assert_eq!(
            refusals(&format!("{EXACT_TIME_FIXTURE}stray: true\n"), &policy),
            ["/stray config.unknown-key"]
        );
    }

    /// The former envelope and the former expectation member are refused,
    /// each naming its replacement.
    #[test]
    fn the_former_spellings_are_refused_with_their_replacements() {
        let policy = policy_for_fixture();
        let retired = EXACT_TIME_FIXTURE.replace(
            "id.registrystack.org/formats/scheduling/fixture/v1alpha1",
            "registry.registrystack.org/scheduling-fixture/v1alpha1",
        );
        assert_eq!(
            refusals(&retired, &policy),
            ["/apiVersion config.retired-api-version"]
        );
        let renamed = EXACT_TIME_FIXTURE.replacen("type: admitted", "outcome: admitted", 1);
        let found = refusals(&renamed, &policy);
        assert!(
            found.contains(&"/cases/0/expect/outcome config.removed-key".to_owned()),
            "{found:?}"
        );
    }

    #[test]
    fn replay_threads_admitted_cases_into_the_ledger() {
        let policy = policy_for_fixture();
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
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
apiVersion: id.registrystack.org/formats/scheduling/fixture/v1alpha1
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
    expect:
      type: admitted
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
    expect:
      type: admitted
      units: 1
      resource: station-1
"#;
        let fixture = read_fixture(yaml, &policy);
        let outcomes = fixture.replay(&policy).expect("replays");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.status == CaseStatus::Pass));
    }

    /// COR-6. A replayed claim is identified by its case name, so two cases
    /// under one name answer to each other's id: the second erases the
    /// first's claim and one reschedule frees two allocations. The reader
    /// refuses the second name at its position, and replay refuses a
    /// fixture built in code the same way.
    #[test]
    fn duplicate_case_names_are_refused_before_any_case_runs() {
        let policy = policy_for_fixture();
        let repeated = EXACT_TIME_FIXTURE.replace(
            "name: same-key-retry-is-refused",
            "name: first-caller-takes-the-last-station",
        );
        assert_eq!(
            refusals(&repeated, &policy),
            ["/cases/1/name scheduling.fixture.duplicate-identifier"]
        );

        let mut fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        let name = fixture.cases[0].name.clone();
        fixture.cases[1].name = name.clone();
        assert_eq!(
            fixture.check(&policy),
            Err(ReplayError::DuplicateCaseName { case: name.clone() })
        );
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::DuplicateCaseName { case: name })
        );
    }

    /// COR-7. A reschedule naming a claim the ledger does not carry excludes
    /// nothing and replaces nothing, so it would replay as an ordinary
    /// booking and pass against an expectation it never tested.
    #[test]
    fn a_reschedule_of_a_claim_the_ledger_does_not_carry_is_reported() {
        let policy = policy_for_fixture();
        let mut fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        fixture.cases[0].request.reschedule_of = Some("booking-404".to_owned());
        assert_eq!(
            fixture.replay(&policy),
            Err(ReplayError::UnknownRescheduleTarget {
                case: fixture.cases[0].name.clone(),
            })
        );
    }

    #[test]
    fn broken_fixtures_stop_before_running() {
        let policy = policy_for_fixture();
        // A code outside the closed vocabulary is refused at its position.
        let unknown = EXACT_TIME_FIXTURE.replace(
            "code: booking.duplicate-active",
            "code: authorization.refused",
        );
        assert_eq!(
            refusals(&unknown, &policy),
            ["/cases/1/expect/code config.invalid-value"]
        );

        let mut fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        fixture.cases[0].request.offering = "no-such-offering".to_owned();
        assert!(matches!(
            fixture.check(&policy),
            Err(ReplayError::UnknownOffering { .. })
        ));
    }

    /// A case naming an offering the project does not declare is a finding
    /// at the case's reference, so a check reports it before any replay.
    #[test]
    fn a_case_naming_an_undeclared_offering_is_found_at_its_reference() {
        let policy = policy_for_fixture();
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        let offering = fixture.cases[1].request.offering.clone();
        let renamed = EXACT_TIME_FIXTURE.replacen(
            &format!("offering: {offering}"),
            "offering: no-such-offering",
            2,
        );
        assert_eq!(
            refusals(&renamed, &policy),
            [
                "/cases/0/request/offering scheduling.fixture.unknown-offering",
                "/cases/1/request/offering scheduling.fixture.unknown-offering",
            ]
        );
    }

    /// A detailed-only expectation code can never match: replay compares the
    /// public projection, so the reader refuses it at its position.
    #[test]
    fn a_detailed_only_expectation_code_is_refused_before_any_case_runs() {
        let policy = policy_for_fixture();
        let detailed = EXACT_TIME_FIXTURE.replace(
            "code: booking.duplicate-active",
            "code: resource.unavailable",
        );
        assert_eq!(
            refusals(&detailed, &policy),
            ["/cases/1/expect/code config.invalid-value"]
        );
    }

    /// A refused value is never repeated in the diagnostic that refuses it.
    #[test]
    fn a_refused_expectation_code_is_not_repeated() {
        let policy = policy_for_fixture();
        let unknown =
            EXACT_TIME_FIXTURE.replace("code: booking.duplicate-active", "code: zz-private-value");
        let report = SchedulingFixture::read(SCHEDULING_FIXTURE_FILE, unknown.as_bytes(), &policy)
            .expect_err("refused");
        assert!(!report.render_human().contains("zz-private-value"));
        assert!(!report
            .to_json_value()
            .to_string()
            .contains("zz-private-value"));
    }

    /// The facts a fixture carries are records the policy accepts, reported
    /// below `/facts` in the fixture itself.
    #[test]
    fn fixture_facts_are_checked_against_the_policy_at_their_position() {
        let policy = policy_for_fixture();
        let repeated = EXACT_TIME_FIXTURE.replace("resourceId: station-2", "resourceId: station-1");
        let found = refusals(&repeated, &policy);
        assert!(
            found
                .iter()
                .all(|finding| finding.starts_with("/facts/pools/0/members/")),
            "{found:?}"
        );
        assert!(!found.is_empty());
    }

    /// A policy whose mode block is missing fails the fixture with a typed
    /// error naming the case and the offering, never a panic: replay must not
    /// assume the policy passed a check it never ran.
    #[test]
    fn a_policy_missing_its_mode_block_fails_the_fixture_not_the_process() {
        let mut policy = policy_for_fixture();
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        policy.offerings[0].exact_time = None;
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
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        policy.openings[0].holiday_set = "no-such-holidays".to_owned();
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
            exceptions: vec![CalendarExceptionRecord {
                id: "systems-training".to_owned(),
                location: "north-counter".to_owned(),
                kind: ExceptionRecordKind::Closure,
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
apiVersion: id.registrystack.org/formats/scheduling/fixture/v1alpha1
kind: SchedulingFixture
name: household-morning
now: 2026-10-09T20:00:00Z
facts:
  locations:
    - id: civic-hall
      timezone: Asia/Bangkok
  windows:
    - id: household-morning-window
      revision: 2
      offering: household-morning
      location: civic-hall
      start: 2026-10-10T01:00:00Z
      end: 2026-10-10T03:00:00Z
      units: 3
      unitsPolicy:
        type: per-recipient
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
cases:
  - name: first-household
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 2
        attendees: 3
      channel: public
      policyRevision: 1
      windowRevision: 2
    expect:
      type: admitted
      units: 2
  - name: second-household-overdraws-the-public-subquota
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: public
      policyRevision: 1
      windowRevision: 2
    expect:
      type: refused
      code: capacity.exhausted
  - name: assisted-household-fits-the-protected-unit
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: assisted
      policyRevision: 1
      windowRevision: 2
    expect:
      type: admitted
      units: 1
"#;
        let policy = read_policy(
            r#"
apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project:
  id: household-days
  version: "3"
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
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
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
channels: [public, assisted]
holdPolicy:
  ttlMinutes: 10
  maximumPerCaller: 2
  because: Households need a few minutes to gather documents.
"#,
        );

        let fixture = read_fixture(yaml, &policy);
        let outcomes = fixture.replay(&policy).expect("replays");
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.status == CaseStatus::Pass),
            "{outcomes:?}"
        );

        let mut closed = read_fixture(yaml, &policy);
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
            code: ProblemCode::LocationClosed,
        };
        let outcomes = closed
            .replay(&policy)
            .expect("the closure reaches admission");
        assert_eq!(outcomes[0].status, CaseStatus::Pass, "{outcomes:?}");
    }

    #[test]
    fn party_counts_read_from_the_fixture_surface() {
        let policy = policy_for_fixture();
        let fixture = read_fixture(EXACT_TIME_FIXTURE, &policy);
        assert_eq!(
            fixture.cases[0].request.admission().party,
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
