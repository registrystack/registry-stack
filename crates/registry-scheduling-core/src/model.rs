// SPDX-License-Identifier: Apache-2.0

//! The source-neutral scheduling model: lifecycle states, the authoritative
//! supply ledger, the environment records admission runs against, and the
//! admission request with its idempotent request hash.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use registry_platform_calendar::{
    CalendarEvaluationError, CalendarException, CalendarExceptionKind,
};
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
};

use crate::diagnostics::{findings_report, FindingArea, PolicyCheckReason, SchedulingDiagnostic};
use crate::naming::{SCHEDULING_RECORDS_API_VERSION, SCHEDULING_RECORDS_KIND};
use crate::policy::{
    valid_hh_mm, valid_iso_date, Channel, PublishedWindow, SchedulingPolicy,
    MAXIMUM_COLLECTION_ENTRIES,
};
use crate::resolve::{location_open_intervals, ResolveError};
use crate::typed::MAXIMUM_UNITS;
use crate::wire::ExternalReference;

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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerClaim {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// The offering whose duplicate-active policy owns this claim.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub offering: String,
    /// The pool member resource (exact time) or the window (arrival) this
    /// claim occupies.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub supply_id: String,
    pub kind: LedgerKind,
    /// The authenticated channel the claim was allocated in, when the supply
    /// carries channel subquotas.
    #[serde(
        default,
        deserialize_with = "optional_channel_name",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Channel>"))]
    pub channel: Option<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Recipient units consumed. Exact-time claims on one member consume one.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
    )]
    pub units: u32,
    /// The duplicate-active key this claim holds, when the offering defines
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_key: Option<String>,
    /// Hold expiry. An expired hold stops consuming capacity at this instant
    /// even when the cleanup worker is delayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A channel written by its closed name, kept as that name.
fn optional_channel_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Channel>::deserialize(deserializer)
        .map(|channel| channel.map(|channel| channel.as_str().to_owned()))
}

/// The authoritative supply ledger at one observed instant, holding exactly
/// the claims that consume capacity now.
///
/// The store is expected to have filtered released, cancelled, and consumed
/// claims before building a snapshot; the evaluator still re-checks hold
/// expiry against `now` so a delayed cleanup worker can never keep an expired
/// hold alive.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
    ///
    /// The key admits one live claim per party for an offering, so a claim
    /// holds it only until the time it occupies has passed. A booking keeps
    /// consuming capacity for overlap forever, but a party whose appointment
    /// is behind them is free to book the offering again.
    pub fn duplicate_active(
        &self,
        offering: &str,
        duplicate_key: &str,
        exclude: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        self.consuming(now).any(|claim| {
            claim.offering == offering
                && claim.duplicate_key.as_deref() == Some(duplicate_key)
                && Some(claim.id.as_str()) != exclude
                && claim.end > now
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationRecord {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// A named IANA timezone such as `Asia/Bangkok`.
    pub timezone: String,
}

/// One interchangeable member of a resource pool.
///
/// `available` carries no reason. Why a member is unavailable is private staff
/// information; the public answer to a caller is that capacity is exhausted.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PoolMember {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub resource_id: String,
    /// The capabilities this member carries. Omitted or `[]`, it carries
    /// none and serves only offerings that require none.
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
    pub available: bool,
}

impl PoolMember {
    /// Whether this member carries every capability an offering requires.
    /// Availability counting and admission share this one predicate, so a
    /// free count never advertises a member admission would refuse.
    #[must_use]
    pub fn serves(&self, requires_capabilities: &[String]) -> bool {
        requires_capabilities
            .iter()
            .all(|wanted| self.capabilities.iter().any(|held| held == wanted))
    }
}

/// A pool of interchangeable resources backing exact-time offerings. A pool is
/// its concrete members, never an independent counter.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourcePool {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub members: Vec<PoolMember>,
}

/// An owned dated exception over local wall-clock time, the record form of
/// `registry_platform_calendar::CalendarException`. An exception is scoped to
/// one location: a closure at one counter never closes another.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarExceptionRecord {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// The location this exception applies to.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub location: String,
    pub kind: ExceptionRecordKind,
    /// The local date, `YYYY-MM-DD`.
    pub date: String,
    /// The local start time, `HH:MM`.
    pub start_time: String,
    /// The local end time, `HH:MM`.
    pub end_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reopens: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
}

/// The layer an exception occupies, mirrored for records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// The environment records an admission runs against: locations, pools,
/// published windows, and dated exceptions. In production these are runtime records; in an offline
/// replay they are fixture facts. The evaluator never reads or mutates them
/// directly; its caller resolves them into the context the evaluator takes.
/// A fixture may omit an empty collection; replay fails fast when a case
/// references a record the facts do not carry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub locations: Vec<LocationRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub pools: Vec<ResourcePool>,
    /// Published arrival-window supply owned by this deployment's operator
    /// records. The policy references these records by identifier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub windows: Vec<PublishedWindow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
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

    #[must_use]
    pub fn window(&self, id: &str) -> Option<&PublishedWindow> {
        self.windows.iter().find(|window| window.id == id)
    }

    /// The checks the store cannot make, against `policy`: the tables it
    /// writes have primary keys and typed columns, so an inconsistent
    /// document would fail mid-swap with a database error naming none of the
    /// author's vocabulary. Every finding points into the records document,
    /// except an offering's reference to a window, which points into the
    /// project.
    #[must_use]
    pub fn check(&self, policy: &SchedulingPolicy) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        let finding = |path: String, reason| SchedulingDiagnostic::records(path, reason);
        for (name, length) in [
            ("/locations", self.locations.len()),
            ("/pools", self.pools.len()),
            ("/exceptions", self.exceptions.len()),
        ] {
            if length > MAXIMUM_COLLECTION_ENTRIES {
                findings.push(finding(name.to_owned(), PolicyCheckReason::TooManyEntries));
            }
        }
        let mut locations = std::collections::BTreeSet::new();
        for (index, location) in self.locations.iter().enumerate() {
            if !locations.insert(location.id.as_str()) {
                findings.push(finding(
                    format!("/locations/{index}/id"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            if location.timezone.parse::<chrono_tz::Tz>().is_err() {
                findings.push(finding(
                    format!("/locations/{index}/timezone"),
                    PolicyCheckReason::UnknownTimezone,
                ));
            }
        }
        let mut pools = std::collections::BTreeSet::new();
        let mut resources = std::collections::BTreeSet::new();
        for (index, pool) in self.pools.iter().enumerate() {
            if !pools.insert(pool.id.as_str()) {
                findings.push(finding(
                    format!("/pools/{index}/id"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            if pool.members.len() > MAXIMUM_COLLECTION_ENTRIES {
                findings.push(finding(
                    format!("/pools/{index}/members"),
                    PolicyCheckReason::TooManyEntries,
                ));
            }
            for (member_index, member) in pool.members.iter().enumerate() {
                if !resources.insert(member.resource_id.as_str()) {
                    findings.push(finding(
                        format!("/pools/{index}/members/{member_index}/resourceId"),
                        PolicyCheckReason::ResourceInManyPools,
                    ));
                }
            }
        }
        findings.extend(policy.check_window_records(&self.windows));
        for (index, window) in self.windows.iter().enumerate() {
            if !locations.contains(window.location.as_str()) {
                findings.push(finding(
                    format!("/windows/{index}/location"),
                    PolicyCheckReason::UnknownLocation,
                ));
            }
            if pools.contains(window.id.as_str()) {
                findings.push(finding(
                    format!("/windows/{index}/id"),
                    PolicyCheckReason::SupplyIdentifierCollision,
                ));
            }
            if let Some(staffing) = &window.staffing {
                if !pools.contains(staffing.pool.as_str()) {
                    findings.push(finding(
                        format!("/windows/{index}/staffing/pool"),
                        PolicyCheckReason::UnknownPool,
                    ));
                }
            }
        }
        let mut exceptions = std::collections::BTreeSet::new();
        for (index, exception) in self.exceptions.iter().enumerate() {
            if !exceptions.insert(exception.id.as_str()) {
                findings.push(finding(
                    format!("/exceptions/{index}/id"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            if !locations.contains(exception.location.as_str()) {
                findings.push(finding(
                    format!("/exceptions/{index}/location"),
                    PolicyCheckReason::UnknownLocation,
                ));
            }
            if !valid_iso_date(&exception.date) {
                findings.push(finding(
                    format!("/exceptions/{index}/date"),
                    PolicyCheckReason::MalformedValue,
                ));
            }
            for (member, time) in [
                ("startTime", &exception.start_time),
                ("endTime", &exception.end_time),
            ] {
                if !valid_hh_mm(time) {
                    findings.push(finding(
                        format!("/exceptions/{index}/{member}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            // Both times are zero-padded `HH:MM`, so their text orders as the
            // times do.
            if valid_hh_mm(&exception.start_time)
                && valid_hh_mm(&exception.end_time)
                && exception.end_time <= exception.start_time
            {
                findings.push(finding(
                    format!("/exceptions/{index}/endTime"),
                    PolicyCheckReason::InvertedRange,
                ));
            }
        }
        // The calendar runs only over records every check above accepted, so
        // its refusal is about the schedule the records and the policy make
        // together, never a malformed value it would repeat.
        if findings.is_empty() {
            for (index, location) in self.locations.iter().enumerate() {
                let exceptions: Vec<_> = self
                    .exceptions
                    .iter()
                    .filter(|exception| exception.location == location.id)
                    .map(CalendarExceptionRecord::borrowed)
                    .collect();
                if let Err(error) =
                    location_open_intervals(policy, &location.id, &location.timezone, &exceptions)
                {
                    // A refusal that names one exception is placed at that
                    // exception; any other concerns the location's schedule.
                    let path = refused_exception(&error)
                        .and_then(|id| {
                            self.exceptions
                                .iter()
                                .position(|exception| exception.id == id)
                        })
                        .map_or_else(
                            || format!("/locations/{index}"),
                            |exception| format!("/exceptions/{exception}"),
                        );
                    findings.push(finding(path, PolicyCheckReason::CalendarRefused));
                }
            }
        }
        findings
    }
}

/// The identifier of the exception a calendar refusal names, if it names
/// one.
fn refused_exception(error: &ResolveError) -> Option<&str> {
    let ResolveError::Calendar(error) = error else {
        return None;
    };
    match error {
        CalendarEvaluationError::InvalidExceptionDate { id }
        | CalendarEvaluationError::DuplicateExceptionId { id }
        | CalendarEvaluationError::ClosureCarriesReopeningFields { id }
        | CalendarEvaluationError::UnknownReopenedClosure { id }
        | CalendarEvaluationError::ReopenAuthorityMissing { id }
        | CalendarEvaluationError::ReopenOutsideClosure { id }
        | CalendarEvaluationError::ReopenOverlapsUnrelatedClosure { id }
        | CalendarEvaluationError::ReopenOutsidePattern { id } => Some(id),
        _ => None,
    }
}

/// The operator records document a deployment applies with
/// `schedulingctl records apply`: its locations, pools and their members,
/// published windows, and dated exceptions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingRecords {
    #[cfg_attr(
        feature = "schema",
        schemars(extend("const" = "id.registrystack.org/formats/scheduling/records/v1alpha1"))
    )]
    pub api_version: String,
    #[cfg_attr(feature = "schema", schemars(extend("const" = "SchedulingRecords")))]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub locations: Vec<LocationRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub pools: Vec<ResourcePool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub windows: Vec<PublishedWindow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub exceptions: Vec<CalendarExceptionRecord>,
}

/// The records document: an envelope with no former spelling, and the units
/// policy members a window renamed.
pub const SCHEDULING_RECORDS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: SCHEDULING_RECORDS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(SCHEDULING_RECORDS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/windows/*/unitsPolicy/kind",
            replacement: "Write type: fixed, per-recipient, or banded-table.",
        },
        RemovedKey {
            pointer: "/windows/*/unitsPolicy/aboveHighestBand/policy",
            replacement: "Write type: refuse or units.",
        },
    ],
};

/// The name a records document read from bytes carries in its diagnostics.
pub const SCHEDULING_RECORDS_FILE: &str = "records.yaml";

impl SchedulingRecords {
    /// Read one records document, refusing what its shape does not carry
    /// with every position.
    pub fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = registry_platform_config::AuthoredExpressions;
        Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&SCHEDULING_RECORDS_FORMAT))
    }

    /// Read one records document and check it against `policy`: every
    /// structural problem, or every finding of [`SchedulingFacts::check`],
    /// each at its position.
    pub fn read(
        file: &str,
        bytes: &[u8],
        policy: &SchedulingPolicy,
    ) -> Result<Decoded<Self>, Report> {
        let decoded = Self::decode(file, bytes)?;
        let findings = decoded.value.facts().check(policy);
        let project_findings: Vec<_> = findings
            .iter()
            .filter(|finding| finding.area != FindingArea::Records)
            .collect();
        // An offering's reference to a window the records do not carry is a
        // finding against the project, which this document cannot place.
        let mut report = findings_report(
            &decoded.document,
            &findings
                .iter()
                .filter(|finding| finding.area == FindingArea::Records)
                .cloned()
                .collect::<Vec<_>>(),
        );
        for finding in project_findings {
            report.push(finding.to_unplaced_diagnostic());
        }
        if report.has_errors() {
            Err(report)
        } else {
            Ok(decoded)
        }
    }

    /// The facts this document carries.
    #[must_use]
    pub fn facts(&self) -> SchedulingFacts {
        SchedulingFacts {
            locations: self.locations.clone(),
            pools: self.pools.clone(),
            windows: self.windows.clone(),
            exceptions: self.exceptions.clone(),
        }
    }

    /// The facts this document carries, consuming it.
    #[must_use]
    pub fn into_facts(self) -> SchedulingFacts {
        SchedulingFacts {
            locations: self.locations,
            pools: self.pools,
            windows: self.windows,
            exceptions: self.exceptions,
        }
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
    /// Opaque record links Scheduling retains with the hold or booking. Their
    /// order is not significant.
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

/// The idempotent hash of an admission request.
///
/// The tuple is fixed in code, in this order, so a field reorder elsewhere can
/// never change a stored hash. The same request always hashes identically;
/// the same idempotency key with a different payload hashes differently, which
/// is exactly the distinction a retry must be able to make.
///
/// Capabilities, prerequisites, and external references are sets the caller
/// happens to send in an order, so they are sorted before hashing: two
/// spellings of one set are one request, and a retry that reorders them
/// replays rather than executing a second time. Repeats are kept, because a
/// hash never edits its input; the HTTP edge refuses repeated references.
#[must_use]
pub fn admission_request_hash(request: &AdmissionRequest) -> String {
    let mut capabilities = request.capabilities.clone();
    capabilities.sort();
    let mut prerequisites = request.prerequisites.clone();
    prerequisites.sort();
    let mut external_references = request.external_references.clone();
    external_references.sort();
    // Preserve the pre-external-reference tuple for requests without links.
    // Their stored idempotency hashes must remain replayable across upgrade.
    let value = if external_references.is_empty() {
        serde_json::to_value((
            &request.offering,
            request.start.to_rfc3339(),
            request.party.recipients,
            request.party.attendees,
            &request.channel,
            &request.duplicate_key,
            request.policy_revision,
            request.window_revision,
            &capabilities,
            &prerequisites,
        ))
    } else {
        serde_json::to_value((
            &request.offering,
            request.start.to_rfc3339(),
            request.party.recipients,
            request.party.attendees,
            &request.channel,
            &request.duplicate_key,
            request.policy_revision,
            request.window_revision,
            &capabilities,
            &prerequisites,
            &external_references,
        ))
    }
    .expect("the fixed tuple always serializes");
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
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
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
            external_references: Vec::new(),
        }
    }

    #[test]
    fn a_confirmed_booking_consumes_but_an_expired_hold_does_not() {
        let now = utc(4, 0);
        let booking = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
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
            offering: "offering-a".to_owned(),
            supply_id: "morning-window".to_owned(),
            kind: LedgerKind::Hold,
            channel: None,
            start: utc(1, 0),
            end: utc(4, 0),
            units: 1,
            duplicate_key: Some("subject:one".to_owned()),
            expires_at: Some(utc(3, 0)),
        };
        let other_offering = LedgerClaim {
            id: "claim-2".to_owned(),
            offering: "offering-b".to_owned(),
            kind: LedgerKind::Booking,
            end: utc(5, 0),
            expires_at: None,
            ..expired_hold.clone()
        };
        let snapshot = LedgerSnapshot {
            claims: vec![expired_hold, other_offering],
        };
        assert!(!snapshot.duplicate_active("offering-a", "subject:one", None, now));
        assert!(snapshot.duplicate_active("offering-b", "subject:one", None, now));
    }

    #[test]
    fn an_elapsed_booking_stops_holding_the_duplicate_key() {
        let booking = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "offering-a".to_owned(),
            supply_id: "morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: None,
            start: utc(1, 0),
            end: utc(2, 0),
            units: 1,
            duplicate_key: Some("subject:one".to_owned()),
            expires_at: None,
        };
        let snapshot = LedgerSnapshot {
            claims: vec![booking],
        };
        // The key names one live booking per party, so it is held while the
        // appointment stands and released once the appointment has passed.
        assert!(snapshot.duplicate_active("offering-a", "subject:one", None, utc(1, 30)));
        assert!(!snapshot.duplicate_active("offering-a", "subject:one", None, utc(2, 0)));
        assert!(!snapshot.duplicate_active("offering-a", "subject:one", None, utc(3, 0)));
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
        assert_eq!(
            admission_request_hash(&request()),
            "sha256:2e9fc6fb84480aff3532f84255ef1ac3a40d46ac60d4eb528671fae633852f69",
            "an empty external-reference set preserves the pre-upgrade idempotency hash"
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

        let other_channel = AdmissionRequest {
            channel: Some("assisted".to_owned()),
            ..request()
        };
        assert_ne!(base, admission_request_hash(&other_channel));
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
        let claim_yaml =
            "id: claim-1\noffering: registry-update-30\nsupplyId: station-1\nkind: booking\n\
                          start: 2026-10-05T02:00:00Z\nend: 2026-10-05T03:00:00Z\nunits: 1\n";
        assert!(serde_norway::from_str::<LedgerClaim>(claim_yaml).is_ok());
        assert!(
            serde_norway::from_str::<LedgerClaim>(&format!("{claim_yaml}note: stray\n")).is_err()
        );

        assert!(serde_norway::from_str::<PartyCounts>("recipients: 1\nattendees: 2\n").is_ok());
        assert!(serde_norway::from_str::<PartyCounts>("recipients: 1\n").is_err());
    }

    /// The wire request carries no exclusion of its own. A caller who names a
    /// claim to leave out of the capacity check is refused at the edge, so no
    /// create path can be handed another caller's allocation to ignore.
    #[test]
    fn an_admission_request_refuses_a_caller_supplied_exclusion() {
        let body = "offering: registry-update-30\nstart: 2026-10-05T02:00:00Z\n\
                    party:\n  recipients: 1\n  attendees: 1\npolicyRevision: 4\n\
                    capabilities: []\nprerequisites: []\n";
        assert!(serde_norway::from_str::<AdmissionRequest>(body).is_ok());
        assert!(
            serde_norway::from_str::<AdmissionRequest>(&format!("{body}rescheduleOf: claim-1\n"))
                .is_err(),
            "the exclusion is the runtime's to supply, never the caller's"
        );
    }

    /// Capabilities, prerequisites, and external references are sets the
    /// caller happens to send in an order. Two spellings of the same set are
    /// the same request, so a retry that reorders them replays instead of
    /// executing again.
    #[test]
    fn set_order_never_changes_the_request_hash() {
        let ordered = AdmissionRequest {
            capabilities: vec!["cap-a".to_owned(), "cap-b".to_owned()],
            prerequisites: vec!["proof-a".to_owned(), "proof-b".to_owned()],
            external_references: vec![
                ExternalReference {
                    product: "registry-casework".to_owned(),
                    record_type: "case".to_owned(),
                    identifier: "case:1".to_owned(),
                },
                ExternalReference {
                    product: "registry-breg".to_owned(),
                    record_type: "record".to_owned(),
                    identifier: "record:2".to_owned(),
                },
            ],
            ..request()
        };
        let reordered = AdmissionRequest {
            capabilities: vec!["cap-b".to_owned(), "cap-a".to_owned()],
            prerequisites: vec!["proof-b".to_owned(), "proof-a".to_owned()],
            external_references: ordered.external_references.iter().rev().cloned().collect(),
            ..request()
        };
        assert_eq!(
            admission_request_hash(&ordered),
            admission_request_hash(&reordered)
        );

        // Membership still counts: a set with a different member is a
        // different request.
        let widened = AdmissionRequest {
            capabilities: vec!["cap-a".to_owned(), "cap-c".to_owned()],
            ..ordered.clone()
        };
        assert_ne!(
            admission_request_hash(&ordered),
            admission_request_hash(&widened)
        );

        let relinked = AdmissionRequest {
            external_references: vec![ExternalReference {
                product: "registry-casework".to_owned(),
                record_type: "case".to_owned(),
                identifier: "case:3".to_owned(),
            }],
            ..ordered.clone()
        };
        assert_ne!(
            admission_request_hash(&ordered),
            admission_request_hash(&relinked)
        );
    }

    const RECORDS_PROJECT: &str = r#"
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
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: stations
      startIncrementMinutes: 30
      maximumRecipients: 1
    cancellationCutoffMinutes: 240
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: ["2026-12-25"]
openings:
  - id: counter-hours
    location: north-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: Counter opening hours reviewed by the office manager.
channels: [public, assisted]
holdPolicy:
  ttlMinutes: 5
  maximumPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

    const RECORDS_HEAD: &str =
        "apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1\n\
        kind: SchedulingRecords\n\
        locations:\n  - id: north-counter\n    timezone: Asia/Bangkok\n";

    fn records_policy() -> SchedulingPolicy {
        SchedulingPolicy::read(crate::AUTHORED_POLICY_FILE, RECORDS_PROJECT.as_bytes())
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value
    }

    /// The diagnostics a refused records document reports, as `pointer code`.
    fn records_refusals(yaml: &str) -> Vec<String> {
        match SchedulingRecords::read(SCHEDULING_RECORDS_FILE, yaml.as_bytes(), &records_policy()) {
            Ok(_) => Vec::new(),
            Err(report) => report
                .diagnostics()
                .iter()
                .map(|diagnostic| format!("{} {}", diagnostic.path, diagnostic.code))
                .collect(),
        }
    }

    #[test]
    fn a_consistent_records_document_reads() {
        let yaml = format!(
            "{RECORDS_HEAD}pools:\n  - id: stations\n    members:\n      - resourceId: station-1\n\
             \x20       capabilities: []\n        available: true\n\
             exceptions:\n  - id: training\n    location: north-counter\n    kind: closure\n\
             \x20   date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '12:30'\n"
        );
        assert_eq!(records_refusals(&yaml), Vec::<String>::new());
        let facts =
            SchedulingRecords::read(SCHEDULING_RECORDS_FILE, yaml.as_bytes(), &records_policy())
                .unwrap()
                .value
                .into_facts();
        assert_eq!(facts.pools[0].members.len(), 1);
        assert_eq!(facts.exceptions[0].id, "training");
    }

    #[test]
    fn inconsistent_records_are_refused_at_their_members() {
        let cases = [
            (
                "apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1\n\
                 kind: SchedulingRecords\n\
                 locations:\n  - id: north-counter\n    timezone: Asia/Bangkok\n\
                 \x20 - id: north-counter\n    timezone: Asia/Bangkok\n"
                    .to_owned(),
                "/locations/1/id scheduling.records.duplicate-identifier",
            ),
            (
                RECORDS_HEAD.replace("Asia/Bangkok", "Mars/Olympus"),
                "/locations/0/timezone scheduling.records.unknown-timezone",
            ),
            (
                format!(
                    "{RECORDS_HEAD}pools:\n  - id: stations\n    members:\n      - resourceId: r1\n\
                     \x20       capabilities: []\n        available: true\n      - resourceId: r1\n\
                     \x20       capabilities: []\n        available: true\n"
                ),
                "/pools/0/members/1/resourceId scheduling.records.resource-in-many-pools",
            ),
            (
                format!(
                    "{RECORDS_HEAD}exceptions:\n  - id: x\n    location: elsewhere\n    kind: closure\n\
                     \x20   date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '12:30'\n"
                ),
                "/exceptions/0/location scheduling.records.unknown-location",
            ),
            (
                format!(
                    "{RECORDS_HEAD}exceptions:\n  - id: x\n    location: north-counter\n    kind: closure\n\
                     \x20   date: '2026-10-7'\n    startTime: '09:00'\n    endTime: '12:30'\n"
                ),
                "/exceptions/0/date scheduling.records.malformed-value",
            ),
            (
                format!(
                    "{RECORDS_HEAD}exceptions:\n  - id: x\n    location: north-counter\n    kind: closure\n\
                     \x20   date: '2026-10-07'\n    startTime: '9:00'\n    endTime: '12:30'\n"
                ),
                "/exceptions/0/startTime scheduling.records.malformed-value",
            ),
            (
                format!(
                    "{RECORDS_HEAD}exceptions:\n  - id: x\n    location: north-counter\n    kind: closure\n\
                     \x20   date: '2026-10-07'\n    startTime: '11:00'\n    endTime: '10:00'\n"
                ),
                "/exceptions/0/endTime scheduling.records.inverted-range",
            ),
            (
                format!("{RECORDS_HEAD}schedule: daily\n"),
                "/schedule config.unknown-key",
            ),
        ];
        for (document, expected) in cases {
            assert_eq!(records_refusals(&document), [expected], "{document}");
        }
    }

    /// The calendar's refusals of the exception layer are placed at the
    /// exception they concern, never only at its location.
    #[test]
    fn exception_layer_semantics_are_refused_at_the_exception() {
        let cases = [
            (
                "opening without a named closure",
                "  - id: reopening\n    location: north-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n",
                "/exceptions/0",
            ),
            (
                "opening without authority",
                "  - id: closure\n    location: north-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '11:00'\n\
                 \x20 - id: reopening\n    location: north-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n    reopens: closure\n",
                "/exceptions/1",
            ),
            (
                "opening names an unknown closure",
                "  - id: reopening\n    location: north-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '09:30'\n    endTime: '10:00'\n    reopens: absent\n    authority: office-manager\n",
                "/exceptions/0",
            ),
            (
                "closure carries reopening fields",
                "  - id: closure\n    location: north-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '10:00'\n    reopens: another\n    authority: office-manager\n",
                "/exceptions/0",
            ),
            (
                "reopening outside the pattern",
                "  - id: early-closure\n    location: north-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '08:00'\n    endTime: '10:00'\n\
                 \x20 - id: early-reopening\n    location: north-counter\n    kind: opening\n    date: '2026-10-07'\n    startTime: '08:00'\n    endTime: '08:30'\n    reopens: early-closure\n    authority: office-manager\n",
                "/exceptions/1",
            ),
        ];
        for (name, exceptions, pointer) in cases {
            assert_eq!(
                records_refusals(&format!("{RECORDS_HEAD}exceptions:\n{exceptions}")),
                [format!("{pointer} scheduling.records.calendar-refused")],
                "{name}"
            );
        }
        // A repeated exception id is the records' own finding, at the
        // repetition.
        assert_eq!(
            records_refusals(&format!(
                "{RECORDS_HEAD}exceptions:\n\
                 \x20 - id: repeated\n    location: north-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '09:00'\n    endTime: '10:00'\n\
                 \x20 - id: repeated\n    location: north-counter\n    kind: closure\n    date: '2026-10-07'\n    startTime: '10:00'\n    endTime: '11:00'\n"
            )),
            ["/exceptions/1/id scheduling.records.duplicate-identifier"]
        );
    }

    #[test]
    fn a_records_document_without_its_envelope_is_refused() {
        let bare = "locations:\n  - id: north-counter\n    timezone: Asia/Bangkok\n";
        let refusals = records_refusals(bare);
        assert!(
            refusals
                .iter()
                .any(|refusal| refusal.starts_with("/apiVersion ")
                    || refusal.starts_with(" config.")),
            "{refusals:?}"
        );
    }
}
