// SPDX-License-Identifier: Apache-2.0

//! The authored scheduling policy: services, offerings, opening patterns,
//! holiday sets, and the hold policy, with the validators a publication gate
//! runs. Published arrival-window supply is an operator record referenced by
//! identifier from an arrival offering.
//!
//! The policy is layer one of the configuration model. It declares what a
//! deployment publishes and why; locations, resource pools, arrival windows,
//! and dated exceptions are runtime records the policy references by
//! identifier but never embeds, so the same published policy governs every
//! environment that resolves those identifiers.

use chrono::{DateTime, Utc};
use registry_platform_hooks::{validate_hooks, HookHandlerSource, HookPhase, HookValidationError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::diagnostics::{PolicyCheckReason, SchedulingDiagnostic};
use crate::naming::SCHEDULING_POLICY_API_VERSION;
use crate::naming::SCHEDULING_POLICY_KIND;
use crate::units::{check_because, RequiredUnitsPolicy};

/// The maximum number of entries one policy collection may carry.
pub const MAXIMUM_COLLECTION_ENTRIES: usize = 256;

/// The maximum bytes of a human-facing label.
pub const MAXIMUM_LABEL_BYTES: usize = 128;

/// One weekday of an opening pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyWeekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl PolicyWeekday {
    #[must_use]
    pub const fn to_chrono(self) -> chrono::Weekday {
        match self {
            Self::Mon => chrono::Weekday::Mon,
            Self::Tue => chrono::Weekday::Tue,
            Self::Wed => chrono::Weekday::Wed,
            Self::Thu => chrono::Weekday::Thu,
            Self::Fri => chrono::Weekday::Fri,
            Self::Sat => chrono::Weekday::Sat,
            Self::Sun => chrono::Weekday::Sun,
        }
    }
}

/// The identity of the deployment the policy governs.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyIdentity {
    pub id: String,
    pub version: u64,
}

/// A service a deployment schedules.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicePolicy {
    pub id: String,
    pub label: String,
}

/// How an offering delivers its service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchedulingMode {
    ExactTime,
    ArrivalWindow,
}

/// The exact-time block of an offering: appointment length, protections, and
/// the interchangeable pool that backs it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTimeOffering {
    pub duration_minutes: u32,
    /// Setup time occupied before the displayed start.
    pub buffer_before_minutes: u32,
    /// Cleanup time occupied after the displayed end.
    pub buffer_after_minutes: u32,
    /// The earliest lead time a caller may book at.
    pub lead_time_minutes: u32,
    /// How far ahead booking is open.
    pub horizon_days: u32,
    /// The pool of interchangeable members backing this offering. A pool is
    /// its members, never an independent counter.
    pub pool: String,
    /// The grid displayed starts must land on.
    pub start_increment_minutes: u32,
    /// The largest party the offering serves.
    pub max_recipients: u32,
}

/// The arrival-window block of an offering.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrivalOffering {
    /// The published window this offering serves arrivals in.
    pub window: String,
    /// The earliest lead time a caller may book the window at.
    pub lead_time_minutes: u32,
    /// How far ahead of the window's start booking is open.
    pub horizon_days: u32,
}

/// One authored reminder offset: a notification intent becomes due this many
/// minutes before the displayed start of an appointment on the offering.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderOffsetPolicy {
    pub minutes_before: u32,
    pub because: String,
}

/// One bookable thing a deployment offers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferingPolicy {
    pub id: String,
    pub service: String,
    pub label: String,
    pub mode: SchedulingMode,
    pub location: String,
    pub because: String,
    /// Present exactly when `mode` is `exact-time`.
    pub exact_time: Option<ExactTimeOffering>,
    /// Present exactly when `mode` is `arrival-window`.
    pub arrival: Option<ArrivalOffering>,
    /// How late before the displayed start a booking may still be cancelled.
    pub cancellation_cutoff_minutes: u32,
    /// Authored reminder offsets for this offering. The runtime mints one
    /// revision-bound intent per offset whose due time is still ahead when
    /// the appointment commits; message transport stays external (INT-02).
    #[serde(default)]
    pub reminders: Vec<ReminderOffsetPolicy>,
    /// The caller attribute an active-booking duplicate check keys on, when
    /// the service defines one. Phone numbers and email addresses are never
    /// valid duplicate keys.
    pub duplicate_active_key: Option<String>,
    /// Capabilities every backing member must have for this offering.
    pub requires_capabilities: Vec<String>,
    /// Prerequisite references a requesting party must hold.
    pub prerequisites: Vec<String>,
}

/// A bounded weekly opening pattern over local wall-clock time. The timezone
/// comes from the location record the pattern references.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpeningPatternPolicy {
    pub id: String,
    pub location: String,
    pub holiday_set: String,
    pub weekdays: Vec<PolicyWeekday>,
    pub start_time: String,
    pub end_time: String,
    pub effective_from: String,
    pub effective_until: String,
    pub because: String,
}

/// A named, revisioned set of holiday dates.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetPolicy {
    pub id: String,
    pub revision: u64,
    pub because: String,
    pub dates: Vec<String>,
}

/// The authenticated channel a subquota limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    Public,
    Assisted,
    Urgent,
    WalkIn,
}

impl Channel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Assisted => "assisted",
            Self::Urgent => "urgent",
            Self::WalkIn => "walk-in",
        }
    }

    /// The channel a name names, or `None` when the name is outside the
    /// closed vocabulary. The vocabulary is the one thing every spelling of
    /// a channel is measured against, whether a policy declares its served
    /// subset or not.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "public" => Some(Self::Public),
            "assisted" => Some(Self::Assisted),
            "urgent" => Some(Self::Urgent),
            "walk-in" => Some(Self::WalkIn),
            _ => None,
        }
    }
}

/// A per-channel ceiling within a window's published capacity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowSubquota {
    pub id: String,
    pub channel: Channel,
    pub units: u32,
    pub because: String,
}

/// What a window says happens to its leftover capacity when it closes. The
/// declaration names an intent; this version of the runtime reads none of
/// it, so `check` refuses a window that declares one rather than accept a
/// promise nothing keeps. There is no default and no borrowing from the
/// next window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeftoverCapacityPolicy {
    /// Leftover units would lapse with the window.
    ExpiresUnused,
    /// Leftover units would become available to the walk-in channel.
    BecomesWalkIn,
}

/// The staffing block a window's supply is carved from, when the window is
/// backed by the same concrete resources an exact-time pool sells.
///
/// A pool that backs a window may not also back an exact-time offering: a
/// window claim occupies the window's own supply while an exact-time claim
/// occupies the member it books, so the two modes would double-book the same
/// staffing in a ledger that cannot see the conflict. That mix is refused at
/// publication whatever this block declares.
///
/// `reserved_members` records how many pool members the window's supply is
/// intended to use. The current ledger does not enforce that partition between
/// windows, so two windows backed by the same pool may not overlap, whatever
/// either staffing block declares. Disjoint windows may reuse the pool.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowStaffing {
    pub pool: String,
    pub reserved_members: Option<u32>,
    pub because: String,
}

/// A published arrival window with its capacity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishedWindow {
    pub id: String,
    pub revision: u64,
    pub offering: String,
    pub location: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Published capacity in the unit basis the units policy defines.
    pub units: u32,
    pub units_policy: RequiredUnitsPolicy,
    pub subquotas: Vec<WindowSubquota>,
    /// Declared intent for the window's leftover capacity. Nothing reads it
    /// in this version, so a declaration is refused at authoring; the field
    /// stays so a refusal can name it.
    #[serde(default)]
    pub leftover: Option<LeftoverCapacityPolicy>,
    pub staffing: Option<WindowStaffing>,
    pub because: String,
}

/// The hold policy every offering inherits.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldPolicy {
    pub ttl_minutes: u32,
    pub max_per_caller: u32,
    pub because: String,
}

/// The shared Registry Stack hook declaration shape. Scheduling adds a closed
/// observer contract: after-commit URL handlers over three appointment
/// lifecycle triggers, with no condition or proposal principal.
pub type HookPolicy = registry_platform_hooks::HookDeclaration;

pub const APPOINTMENT_CONFIRMED_TRIGGER: &str = "appointment.confirmed";
pub const APPOINTMENT_RESCHEDULED_TRIGGER: &str = "appointment.rescheduled";
pub const APPOINTMENT_CANCELLED_TRIGGER: &str = "appointment.cancelled";

const APPOINTMENT_OBSERVER_FIELDS: &[&str] = &[
    "appointmentId",
    "end",
    "offering",
    "policyRevision",
    "revision",
    "start",
    "state",
];
const CANCELLATION_OBSERVER_FIELDS: &[&str] = &["appointmentId", "revision", "state"];

/// The authored scheduling policy package.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingPolicy {
    pub api_version: String,
    pub kind: String,
    pub scheduling: PolicyIdentity,
    pub services: Vec<ServicePolicy>,
    pub offerings: Vec<OfferingPolicy>,
    pub holiday_sets: Vec<HolidaySetPolicy>,
    pub openings: Vec<OpeningPatternPolicy>,
    /// The channels this deployment declares it serves. The vocabulary is
    /// closed by the `Channel` type itself; a declaration narrows it to the
    /// served subset, every subquota must draw on a declared channel, and a
    /// request naming anything else is refused. An absent declaration
    /// declares nothing beyond the vocabulary.
    #[serde(default)]
    pub channels: Vec<Channel>,
    pub hold_policy: HoldPolicy,
    #[serde(default)]
    pub hooks: Vec<HookPolicy>,
}

/// Parse a policy from its authored YAML, with the failing path preserved.
pub fn parse_policy_yaml(
    text: &str,
) -> Result<SchedulingPolicy, serde_path_to_error::Error<serde_norway::Error>> {
    let deserializer = serde_norway::Deserializer::from_str(text);
    serde_path_to_error::deserialize(deserializer)
}

impl SchedulingPolicy {
    #[must_use]
    pub fn offering(&self, id: &str) -> Option<&OfferingPolicy> {
        self.offerings.iter().find(|offering| offering.id == id)
    }

    #[must_use]
    pub fn holiday_set(&self, id: &str) -> Option<&HolidaySetPolicy> {
        self.holiday_sets.iter().find(|set| set.id == id)
    }

    /// The canonical digest of this policy package: `sha256:` followed by 64
    /// hex digits over the canonical JSON of the envelope and policy. The
    /// same policy always digests identically; any authored change does not.
    pub fn policy_digest(&self) -> String {
        let envelope = serde_json::json!({
            "schema": SCHEDULING_POLICY_API_VERSION,
            "policy": self,
        });
        let canonical = registry_platform_canonical_json::canonicalize_json(&envelope)
            .expect("a policy envelope always canonicalizes");
        let digest = Sha256::digest(&canonical);
        format!("sha256:{}", hex(&digest))
    }

    /// Check the whole policy. Every finding names the path that failed.
    pub fn check(&self) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        if self.api_version != SCHEDULING_POLICY_API_VERSION {
            findings.push(SchedulingDiagnostic::new(
                "apiVersion",
                PolicyCheckReason::UnsupportedApiVersion,
            ));
        }
        if self.kind != SCHEDULING_POLICY_KIND {
            findings.push(SchedulingDiagnostic::new(
                "kind",
                PolicyCheckReason::UnsupportedKind,
            ));
        }
        if !valid_identifier(&self.scheduling.id) {
            findings.push(SchedulingDiagnostic::new(
                "scheduling.id",
                PolicyCheckReason::InvalidIdentifier,
            ));
        }
        if self.scheduling.version == 0 {
            findings.push(SchedulingDiagnostic::new(
                "scheduling.version",
                PolicyCheckReason::InvalidBound,
            ));
        }

        check_collection_non_empty(&self.services, "services", &mut findings);
        check_collection_non_empty(&self.offerings, "offerings", &mut findings);
        check_collection_non_empty(&self.holiday_sets, "holidaySets", &mut findings);
        check_collection_non_empty(&self.openings, "openings", &mut findings);
        check_collection_bound(&self.services, "services", &mut findings);
        check_collection_bound(&self.offerings, "offerings", &mut findings);
        check_collection_bound(&self.holiday_sets, "holidaySets", &mut findings);
        check_collection_bound(&self.openings, "openings", &mut findings);

        // A declared channel set is a closed list of the channels this
        // deployment serves; naming one twice declares it once.
        let mut declared_channels: Vec<Channel> = Vec::new();
        for (index, channel) in self.channels.iter().enumerate() {
            if declared_channels.contains(channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("channels[{index}]"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            declared_channels.push(*channel);
        }

        let mut service_ids = Vec::new();
        for (index, service) in self.services.iter().enumerate() {
            let path = format!("services[{index}]");
            if !valid_identifier(&service.id) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.id"),
                    PolicyCheckReason::InvalidIdentifier,
                ));
            }
            if service.label.trim().is_empty() || service.label.len() > MAXIMUM_LABEL_BYTES {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.label"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            push_unique(&mut service_ids, &service.id, &path, &mut findings);
        }

        for (index, set) in self.holiday_sets.iter().enumerate() {
            let path = format!("holidaySets[{index}]");
            // A holiday set with no dates is complete: it observes none.
            if set.revision == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.revision"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            check_because(&set.because, &format!("{path}.because"), &mut findings);
            check_identifier(&set.id, &format!("{path}.id"), &mut findings);
            for (date_index, date) in set.dates.iter().enumerate() {
                if !valid_iso_date(date) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.dates[{date_index}]"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            self.check_unique_id(&set.id, &path, "holidaySets", &mut findings);
        }

        for (index, opening) in self.openings.iter().enumerate() {
            let path = format!("openings[{index}]");
            check_identifier(&opening.id, &format!("{path}.id"), &mut findings);
            check_identifier(
                &opening.location,
                &format!("{path}.location"),
                &mut findings,
            );
            if self.holiday_set(&opening.holiday_set).is_none() {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.holidaySet"),
                    PolicyCheckReason::UnknownHolidaySet,
                ));
            }
            check_collection_non_empty(
                &opening.weekdays,
                &format!("{path}.weekdays"),
                &mut findings,
            );
            // A value outside its grammar is named where it stands, and the
            // range it belongs to is left unjudged: comparing text that is not
            // a clock, or not a date, would answer a question the author never
            // asked.
            for (field, value) in [
                ("startTime", &opening.start_time),
                ("endTime", &opening.end_time),
            ] {
                if !valid_hh_mm(value) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.{field}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            let clocks_are_clocks =
                valid_hh_mm(&opening.start_time) && valid_hh_mm(&opening.end_time);
            if clocks_are_clocks && opening.start_time >= opening.end_time {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.endTime"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            for (field, value) in [
                ("effectiveFrom", &opening.effective_from),
                ("effectiveUntil", &opening.effective_until),
            ] {
                if !valid_iso_date(value) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.{field}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            let dates_are_dates =
                valid_iso_date(&opening.effective_from) && valid_iso_date(&opening.effective_until);
            if dates_are_dates && opening.effective_from > opening.effective_until {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.effectiveUntil"),
                    PolicyCheckReason::InvalidBound,
                ));
            } else if let (Some(from), Some(until)) = (
                chrono::NaiveDate::parse_from_str(&opening.effective_from, "%Y-%m-%d").ok(),
                chrono::NaiveDate::parse_from_str(&opening.effective_until, "%Y-%m-%d").ok(),
            ) {
                // The weekly expansion refuses a span this wide at evaluation
                // time; the authoring check refuses it first, so a checked
                // policy never deploys into a runtime that cannot expand it.
                if until.signed_duration_since(from).num_days()
                    > i64::from(registry_platform_calendar::MAXIMUM_PATTERN_SPAN_DAYS)
                {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.effectiveUntil"),
                        PolicyCheckReason::PatternSpanTooLarge,
                    ));
                }
            }
            check_because(&opening.because, &format!("{path}.because"), &mut findings);
            self.check_unique_id(&opening.id, &path, "openings", &mut findings);
        }

        for (index, offering) in self.offerings.iter().enumerate() {
            self.check_offering(offering, index, &mut findings);
        }
        for (index, offering) in self.offerings.iter().enumerate() {
            if let Some(arrival) = &offering.arrival {
                if self.sells_pool(&arrival.window) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("offerings[{index}].arrival.window"),
                        PolicyCheckReason::SupplyIdentifierCollision,
                    ));
                }
            }
        }

        check_because(
            &self.hold_policy.because,
            "holdPolicy.because",
            &mut findings,
        );
        if self.hold_policy.ttl_minutes == 0 || self.hold_policy.max_per_caller == 0 {
            findings.push(SchedulingDiagnostic::new(
                "holdPolicy",
                PolicyCheckReason::InvalidBound,
            ));
        }

        check_collection_bound(&self.hooks, "hooks", &mut findings);
        for (index, hook) in self.hooks.iter().enumerate() {
            check_identifier(&hook.id, &format!("hooks[{index}].id"), &mut findings);
            check_scheduling_hook(hook, index, &mut findings);
        }
        if let Err(error) = validate_hooks(&self.hooks) {
            findings.push(hook_validation_diagnostic(&error));
        }

        findings
    }

    fn check_offering(
        &self,
        offering: &OfferingPolicy,
        index: usize,
        findings: &mut Vec<SchedulingDiagnostic>,
    ) {
        let path = format!("offerings[{index}]");
        check_identifier(&offering.id, &format!("{path}.id"), findings);
        check_identifier(&offering.service, &format!("{path}.service"), findings);
        if !service_ids_contains(self, &offering.service) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.service"),
                PolicyCheckReason::UnknownService,
            ));
        }
        check_identifier(&offering.location, &format!("{path}.location"), findings);
        if offering.label.trim().is_empty() || offering.label.len() > MAXIMUM_LABEL_BYTES {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.label"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        check_because(&offering.because, &format!("{path}.because"), findings);
        self.check_unique_id(&offering.id, &path, "offerings", findings);

        let (block, block_reason_path) = match offering.mode {
            SchedulingMode::ExactTime => (offering.exact_time.is_some(), "exactTime"),
            SchedulingMode::ArrivalWindow => (offering.arrival.is_some(), "arrival"),
        };
        if !block {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.{block_reason_path}"),
                PolicyCheckReason::MissingModeField,
            ));
        }
        match offering.mode {
            SchedulingMode::ExactTime => {
                if offering.arrival.is_some() {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.arrival"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
                if let Some(exact) = &offering.exact_time {
                    let block_path = format!("{path}.exactTime");
                    if exact.duration_minutes == 0
                        || exact.lead_time_minutes == 0
                        || exact.horizon_days == 0
                        || exact.start_increment_minutes == 0
                        || exact.max_recipients == 0
                    {
                        findings.push(SchedulingDiagnostic::new(
                            block_path.clone(),
                            PolicyCheckReason::InvalidBound,
                        ));
                    }
                    check_identifier(&exact.pool, &format!("{block_path}.pool"), findings);
                    let horizon_minutes = u64::from(exact.horizon_days) * 24 * 60;
                    if u64::from(exact.lead_time_minutes) > horizon_minutes {
                        findings.push(SchedulingDiagnostic::new(
                            format!("{block_path}.leadTimeMinutes"),
                            PolicyCheckReason::InvalidBound,
                        ));
                    }
                }
            }
            SchedulingMode::ArrivalWindow => {
                if offering.exact_time.is_some() {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.exactTime"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
                if let Some(arrival) = &offering.arrival {
                    let block_path = format!("{path}.arrival");
                    check_identifier(&arrival.window, &format!("{block_path}.window"), findings);
                    if arrival.lead_time_minutes == 0 || arrival.horizon_days == 0 {
                        findings.push(SchedulingDiagnostic::new(
                            block_path.clone(),
                            PolicyCheckReason::InvalidBound,
                        ));
                    }
                    let horizon_minutes = u64::from(arrival.horizon_days) * 24 * 60;
                    if u64::from(arrival.lead_time_minutes) > horizon_minutes {
                        findings.push(SchedulingDiagnostic::new(
                            format!("{block_path}.leadTimeMinutes"),
                            PolicyCheckReason::InvalidBound,
                        ));
                    }
                }
            }
        }

        if let Some(key) = &offering.duplicate_active_key {
            check_identifier(key, &format!("{path}.duplicateActiveKey"), findings);
        }
        check_collection_bound(&offering.reminders, &format!("{path}.reminders"), findings);
        let mut reminder_offsets: Vec<u32> = Vec::new();
        for (offset_index, reminder) in offering.reminders.iter().enumerate() {
            let reminder_path = format!("{path}.reminders[{offset_index}]");
            if reminder.minutes_before == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{reminder_path}.minutesBefore"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            // Two offsets at the same distance would mint two intents due at
            // the same instant for one appointment: one reminder per moment.
            if reminder_offsets.contains(&reminder.minutes_before) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{reminder_path}.minutesBefore"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            } else {
                reminder_offsets.push(reminder.minutes_before);
            }
            check_because(
                &reminder.because,
                &format!("{reminder_path}.because"),
                findings,
            );
        }
        // A request carries the capabilities and prerequisites that satisfy
        // these, and the request edge bounds its own lists at the same
        // maximum. An offering requiring more than that bound publishes
        // cleanly and refuses every admissible request, so it is refused
        // here instead.
        check_collection_bound(
            &offering.requires_capabilities,
            &format!("{path}.requiresCapabilities"),
            findings,
        );
        check_collection_bound(
            &offering.prerequisites,
            &format!("{path}.prerequisites"),
            findings,
        );
        for capability in &offering.requires_capabilities {
            if !valid_identifier(capability) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.requiresCapabilities"),
                    PolicyCheckReason::InvalidIdentifier,
                ));
            }
        }
        for prerequisite in &offering.prerequisites {
            if !valid_reference(prerequisite) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.prerequisites"),
                    PolicyCheckReason::InvalidIdentifier,
                ));
            }
        }
    }

    /// Validate the published windows in one environment-records document
    /// against this policy. Policy authoring can validate the identifier
    /// reference alone; existence and the window's capacity contract belong
    /// to the operator records that carry the supply.
    pub fn check_window_records(&self, windows: &[PublishedWindow]) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        check_collection_bound(windows, "windows", &mut findings);
        for (index, offering) in self.offerings.iter().enumerate() {
            if let Some(arrival) = &offering.arrival {
                match windows.iter().find(|window| window.id == arrival.window) {
                    None => findings.push(SchedulingDiagnostic::new(
                        format!("offerings[{index}].arrival.window"),
                        PolicyCheckReason::UnknownWindow,
                    )),
                    Some(window)
                        if window.offering != offering.id
                            || window.location != offering.location =>
                    {
                        findings.push(SchedulingDiagnostic::new(
                            format!("offerings[{index}].arrival.window"),
                            PolicyCheckReason::MismatchedReference,
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        for (index, window) in windows.iter().enumerate() {
            self.check_window(window, windows, index, &mut findings);
        }
        findings
    }

    fn check_window(
        &self,
        window: &PublishedWindow,
        windows: &[PublishedWindow],
        index: usize,
        findings: &mut Vec<SchedulingDiagnostic>,
    ) {
        let path = format!("windows[{index}]");
        check_identifier(&window.id, &format!("{path}.id"), findings);
        if window.revision == 0 {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.revision"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        check_because(&window.because, &format!("{path}.because"), findings);
        if windows.iter().filter(|other| other.id == window.id).count() > 1 {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.id"),
                PolicyCheckReason::DuplicateIdentifier,
            ));
        }
        if window.units == 0 || window.units > i32::MAX as u32 {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.units"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        if window.end <= window.start {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.end"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        findings.extend(window.units_policy.check(&format!("{path}.unitsPolicy")));

        // A pool and a window anchor their capacity transactions on one row
        // keyed by the identifier, so the two supply namespaces must stay
        // disjoint. Sharing an identifier makes the two publish paths write
        // the same row: one aborts on the key, the other leaves the wrong
        // kind standing and the next records swap deletes the anchor the
        // pool still depends on.
        if self.sells_pool(&window.id) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.id"),
                PolicyCheckReason::SupplyIdentifierCollision,
            ));
        }

        if window.leftover.is_some() {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.leftover"),
                PolicyCheckReason::LeftoverUnsupported,
            ));
        }

        match self.offering(&window.offering) {
            None => findings.push(SchedulingDiagnostic::new(
                format!("{path}.offering"),
                PolicyCheckReason::UnknownOffering,
            )),
            Some(offering) => {
                if offering.mode != SchedulingMode::ArrivalWindow
                    || offering
                        .arrival
                        .as_ref()
                        .is_none_or(|arrival| arrival.window != window.id)
                    || offering.location != window.location
                {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}.offering"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
            }
        }

        let mut channels = Vec::new();
        let mut subquota_units = 0_u32;
        for (subquota_index, subquota) in window.subquotas.iter().enumerate() {
            let subquota_path = format!("{path}.subquotas[{subquota_index}]");
            check_identifier(&subquota.id, &format!("{subquota_path}.id"), findings);
            check_because(
                &subquota.because,
                &format!("{subquota_path}.because"),
                findings,
            );
            if subquota.units == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}.units"),
                    PolicyCheckReason::InvalidBound,
                ));
            } else {
                subquota_units = subquota_units.saturating_add(subquota.units);
            }
            if channels.contains(&subquota.channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}.channel"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            // A declared set is closed: a subquota may not limit capacity
            // for a channel the deployment does not say it serves.
            if !self.channels.is_empty() && !self.channels.contains(&subquota.channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}.channel"),
                    PolicyCheckReason::UnknownChannel,
                ));
            }
            channels.push(subquota.channel);
        }
        if subquota_units > window.units {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.subquotas"),
                PolicyCheckReason::SubquotaOverdrawn,
            ));
        }

        if let Some(staffing) = &window.staffing {
            check_identifier(&staffing.pool, &format!("{path}.staffing.pool"), findings);
            check_because(
                &staffing.because,
                &format!("{path}.staffing.because"),
                findings,
            );
            // A pool that backs a window may not also back an exact-time
            // offering: the two modes count the same staffing differently, so
            // the mix would double-book it in a ledger that cannot see the
            // conflict. No authored partition attributes the supply across
            // the two modes, so the refusal stands whatever this block
            // declares.
            let mixed_modes = self.offerings.iter().any(|offering| {
                offering
                    .exact_time
                    .as_ref()
                    .is_some_and(|exact| exact.pool == staffing.pool)
            });
            if mixed_modes {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.staffing.pool"),
                    PolicyCheckReason::SharedSupplyUnpartitioned,
                ));
            }
            // Window claims occupy their window ids, so the ledger cannot
            // enforce an authored staffing partition between two windows.
            // Refuse every overlapping use of one pool; disjoint windows may
            // reuse it because their staffing cannot be booked twice at once.
            let doubly_claimed = windows.iter().any(|other| {
                other.id != window.id
                    && other.staffing.as_ref().is_some_and(|other_staffing| {
                        other_staffing.pool == staffing.pool
                            && other.start < window.end
                            && window.start < other.end
                    })
            });
            if doubly_claimed {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}.staffing.pool"),
                    PolicyCheckReason::SharedSupplyUnpartitioned,
                ));
            }
        }
    }

    /// Whether any exact-time offering draws on the pool named `id`. Those
    /// are the pools publication anchors, so they are the identifiers a
    /// window may not take.
    fn sells_pool(&self, id: &str) -> bool {
        self.offerings.iter().any(|offering| {
            offering
                .exact_time
                .as_ref()
                .is_some_and(|exact| exact.pool == id)
        })
    }

    fn check_unique_id(
        &self,
        id: &str,
        path: &str,
        collection: &str,
        findings: &mut Vec<SchedulingDiagnostic>,
    ) {
        let duplicate = match collection {
            "offerings" => {
                self.offerings
                    .iter()
                    .filter(|offering| offering.id == id)
                    .count()
                    > 1
            }
            "openings" => {
                self.openings
                    .iter()
                    .filter(|opening| opening.id == id)
                    .count()
                    > 1
            }
            "holidaySets" => self.holiday_sets.iter().filter(|set| set.id == id).count() > 1,
            _ => false,
        };
        if duplicate {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.id"),
                PolicyCheckReason::DuplicateIdentifier,
            ));
        }
    }
}

fn check_scheduling_hook(
    hook: &HookPolicy,
    index: usize,
    findings: &mut Vec<SchedulingDiagnostic>,
) {
    let path = format!("hooks[{index}]");
    if hook.phase != HookPhase::After || !matches!(hook.handler, HookHandlerSource::Url { .. }) {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}.phase"),
            PolicyCheckReason::UnsupportedHookPhase,
        ));
    }
    if let HookHandlerSource::Url { destination_id } = &hook.handler {
        if !valid_hook_destination_id(destination_id) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.handler.destinationId"),
                PolicyCheckReason::InvalidHookDestination,
            ));
        }
    }
    let allowed_projection = match hook.trigger.as_str() {
        APPOINTMENT_CONFIRMED_TRIGGER | APPOINTMENT_RESCHEDULED_TRIGGER => {
            Some(APPOINTMENT_OBSERVER_FIELDS)
        }
        APPOINTMENT_CANCELLED_TRIGGER => Some(CANCELLATION_OBSERVER_FIELDS),
        _ => None,
    };
    let Some(allowed_projection) = allowed_projection else {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}.trigger"),
            PolicyCheckReason::UnsupportedHookTrigger,
        ));
        return;
    };
    if hook.when.is_some() {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}.when"),
            PolicyCheckReason::UnsupportedHookCondition,
        ));
    }
    if hook.principal.is_some() {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}.principal"),
            PolicyCheckReason::UnsupportedHookPrincipal,
        ));
    }
    for field in &hook.projection {
        if !allowed_projection.contains(&field.as_str()) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}.projection"),
                PolicyCheckReason::UnsupportedHookProjection,
            ));
            break;
        }
    }
}

fn valid_hook_destination_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

/// One window, or one channel slice of a window, whose proposed capacity fell
/// below what is already committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityReduction {
    pub window: String,
    /// The channel whose subquota the reduction strands, or `None` when the
    /// deficit is the window total's.
    pub channel: Option<Channel>,
    pub committed_units: u32,
    pub proposed_units: u32,
}

/// Assess proposed window records against the commitments already standing in
/// a ledger snapshot.
///
/// A normal capacity reduction that would leave confirmed bookings and live
/// holds above the proposed capacity is rejected: it comes back here as a
/// finding with the deficit, never as a successful validation. Both levels of
/// published capacity are assessed on both sides of the proposal: the window
/// total, and each channel subquota, which is its own committed slice a
/// proposal may strand by reducing it, by dropping it, or by introducing it
/// below what the channel already holds. A window the proposal keeps is
/// assessed over the interval it now publishes: a claim whose interval the
/// new window no longer covers is a commitment the proposal strands against
/// zero, and no longer capacity the moved window must cover. An emergency
/// reduction is a different operation entirely, recorded as an incident with
/// its affected bookings, and does not pass through this assessment.
pub fn assess_window_record_impact(
    current: &[PublishedWindow],
    proposed: &[PublishedWindow],
    snapshot: &crate::model::LedgerSnapshot,
    now: DateTime<Utc>,
) -> Vec<CapacityReduction> {
    let mut reductions = Vec::new();
    let window_ids: BTreeSet<&str> = current
        .iter()
        .map(|window| window.id.as_str())
        .chain(
            snapshot
                .consuming(now)
                .map(|claim| claim.supply_id.as_str()),
        )
        .collect();
    for window_id in window_ids {
        let current_window = current.iter().find(|candidate| candidate.id == window_id);
        let proposed_window = proposed.iter().find(|candidate| candidate.id == window_id);
        let proposed_units = proposed_window.map_or(0, |proposed| proposed.units);
        // A window the proposal drops has no interval left to meet, so every
        // claim counts against the zero it proposes.
        let committed = match proposed_window {
            Some(proposed) => {
                units_committed_within(snapshot, window_id, None, proposed.start, proposed.end, now)
            }
            None => snapshot.window_units_allocated(window_id, None, None, now),
        };
        if committed > proposed_units {
            reductions.push(CapacityReduction {
                window: window_id.to_owned(),
                channel: None,
                committed_units: committed,
                proposed_units,
            });
        }
        if let Some(proposed) = proposed_window {
            // The commitments the proposed interval no longer covers are
            // stranded: the proposal publishes no capacity where they stand,
            // which is a reduction to zero for them.
            let stranded =
                units_committed_outside(snapshot, window_id, proposed.start, proposed.end, now);
            if stranded > 0 {
                reductions.push(CapacityReduction {
                    window: window_id.to_owned(),
                    channel: None,
                    committed_units: stranded,
                    proposed_units: 0,
                });
            }
        }
        // A subquota dropped from the proposal proposes zero for its channel.
        for subquota in current_window
            .map(|window| window.subquotas.as_slice())
            .unwrap_or_default()
        {
            let proposed_subquota = proposed_window
                .and_then(|proposed| {
                    proposed
                        .subquotas
                        .iter()
                        .find(|candidate| candidate.channel == subquota.channel)
                })
                .map_or(0, |candidate| candidate.units);
            if proposed_subquota >= subquota.units {
                continue;
            }
            let committed_channel = match proposed_window {
                Some(proposed) => units_committed_within(
                    snapshot,
                    window_id,
                    Some(subquota.channel.as_str()),
                    proposed.start,
                    proposed.end,
                    now,
                ),
                None => snapshot.window_units_allocated(
                    window_id,
                    Some(subquota.channel.as_str()),
                    None,
                    now,
                ),
            };
            if committed_channel > proposed_subquota {
                reductions.push(CapacityReduction {
                    window: window_id.to_owned(),
                    channel: Some(subquota.channel),
                    committed_units: committed_channel,
                    proposed_units: proposed_subquota,
                });
            }
        }
        // A subquota that exists only in the proposal introduces a ceiling
        // the channel never had, so the commitments it already holds are
        // assessed against it: a slice below them strands them exactly as a
        // reduction of an existing slice would.
        if let Some(proposed) = proposed_window {
            for subquota in &proposed.subquotas {
                let already_published = current_window.is_some_and(|window| {
                    window
                        .subquotas
                        .iter()
                        .any(|current| current.channel == subquota.channel)
                });
                if already_published {
                    continue;
                }
                let committed_channel = units_committed_within(
                    snapshot,
                    window_id,
                    Some(subquota.channel.as_str()),
                    proposed.start,
                    proposed.end,
                    now,
                );
                if committed_channel > subquota.units {
                    reductions.push(CapacityReduction {
                        window: window_id.to_owned(),
                        channel: Some(subquota.channel),
                        committed_units: committed_channel,
                        proposed_units: subquota.units,
                    });
                }
            }
        }
    }
    reductions
}

/// Recipient units standing against a window's supply at `now`, counting only
/// claims whose occupied interval is fully contained in `[start, end)`, so a
/// proposal that moves or shortens the window cannot count a partly stranded
/// commitment against the capacity it still publishes.
fn units_committed_within(
    snapshot: &crate::model::LedgerSnapshot,
    window_id: &str,
    channel: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
) -> u32 {
    snapshot
        .consuming(now)
        .filter(|claim| {
            claim.supply_id == window_id
                && channel.is_none_or(|wanted| claim.channel.as_deref() == Some(wanted))
                && start <= claim.start
                && claim.end <= end
        })
        .map(|claim| claim.units)
        // Saturating, for the same reason the snapshot's own sum saturates:
        // a total past u32 units must refuse, never wrap toward zero.
        .fold(0, u32::saturating_add)
}

/// Recipient units standing against a window's supply at `now` whose occupied
/// interval is not fully contained in `[start, end)`: the commitments a
/// proposal publishing that interval no longer covers.
fn units_committed_outside(
    snapshot: &crate::model::LedgerSnapshot,
    window_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
) -> u32 {
    snapshot
        .consuming(now)
        .filter(|claim| claim.supply_id == window_id && !(start <= claim.start && claim.end <= end))
        .map(|claim| claim.units)
        .fold(0, u32::saturating_add)
}

fn service_ids_contains(policy: &SchedulingPolicy, id: &str) -> bool {
    policy.services.iter().any(|service| service.id == id)
}

fn hook_validation_diagnostic(error: &HookValidationError) -> SchedulingDiagnostic {
    match error {
        HookValidationError::EmptyHookId { index } => SchedulingDiagnostic::new(
            format!("hooks[{index}].id"),
            PolicyCheckReason::InvalidIdentifier,
        ),
        HookValidationError::DuplicateHookId { index, .. } => SchedulingDiagnostic::new(
            format!("hooks[{index}].id"),
            PolicyCheckReason::DuplicateIdentifier,
        ),
        HookValidationError::BeforePhaseRemoteHandler { index, .. } => SchedulingDiagnostic::new(
            format!("hooks[{index}].phase"),
            PolicyCheckReason::UnsupportedHookPhase,
        ),
        HookValidationError::AbiMissing { index, .. }
        | HookValidationError::AbiUnknown { index, .. } => SchedulingDiagnostic::new(
            format!("hooks[{index}].handler.abi"),
            PolicyCheckReason::UnsupportedHookAbi,
        ),
        _ => SchedulingDiagnostic::new("hooks", PolicyCheckReason::InvalidHookDeclaration),
    }
}

fn push_unique(
    seen: &mut Vec<String>,
    id: &str,
    path: &str,
    findings: &mut Vec<SchedulingDiagnostic>,
) {
    if seen.iter().any(|known| known == id) {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}.id"),
            PolicyCheckReason::DuplicateIdentifier,
        ));
    } else {
        seen.push(id.to_owned());
    }
}

fn check_collection_non_empty<T>(
    collection: &[T],
    path: &str,
    findings: &mut Vec<SchedulingDiagnostic>,
) {
    if collection.is_empty() {
        findings.push(SchedulingDiagnostic::new(
            path,
            PolicyCheckReason::EmptyCollection,
        ));
    }
}

fn check_collection_bound<T>(
    collection: &[T],
    path: &str,
    findings: &mut Vec<SchedulingDiagnostic>,
) {
    if collection.len() > MAXIMUM_COLLECTION_ENTRIES {
        findings.push(SchedulingDiagnostic::new(
            path,
            PolicyCheckReason::InvalidBound,
        ));
    }
}

fn check_identifier(id: &str, path: &str, findings: &mut Vec<SchedulingDiagnostic>) {
    if !valid_identifier(id) {
        findings.push(SchedulingDiagnostic::new(
            path,
            PolicyCheckReason::InvalidIdentifier,
        ));
    }
}

/// The identifier grammar shared by every policy id: non-empty, at most 64
/// bytes, starting with a lowercase letter and continuing with lowercase
/// letters, digits, and hyphens.
#[must_use]
pub fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// A reference an offering may require a party to hold: a stable scoped
/// identifier such as `case:1234` or `urn:...`.
#[must_use]
pub fn valid_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_hh_mm(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 5
        && bytes[2] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
        && value[..2].parse::<u32>().is_ok_and(|hour| hour < 24)
        && value[3..].parse::<u32>().is_ok_and(|minute| minute < 60)
}

fn valid_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
        && chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
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
    use crate::model::{LedgerClaim, LedgerKind, PartyCounts};
    use chrono::TimeZone as _;

    fn utc(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 10, hour, minute, 0).unwrap()
    }

    pub fn minimal_exact_time_policy() -> SchedulingPolicy {
        let yaml = r#"
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
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: update-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    requiresCapabilities: []
    prerequisites: []
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
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;
        serde_norway::from_str(yaml).expect("the minimal policy parses")
    }

    pub fn household_window_policy() -> SchedulingPolicy {
        let yaml = r#"
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
"#;
        serde_norway::from_str(yaml).expect("the household policy parses")
    }

    fn household_windows() -> Vec<PublishedWindow> {
        let records: crate::model::SchedulingFacts = serde_norway::from_str(
            r#"
windows:
  - id: household-morning-window
    revision: 2
    offering: household-morning
    location: civic-hall
    start: 2026-10-10T08:00:00Z
    end: 2026-10-10T10:00:00Z
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
    because: The Saturday morning household block, sized for two officers.
"#,
        )
        .expect("the household window records parse");
        records.windows
    }

    #[test]
    fn the_minimal_policies_carry_no_findings() {
        assert!(
            minimal_exact_time_policy().check().is_empty(),
            "{:?}",
            minimal_exact_time_policy().check()
        );
        assert!(
            household_window_policy().check().is_empty(),
            "{:?}",
            household_window_policy().check()
        );
    }

    #[test]
    fn the_policy_digest_is_stable_and_moves_with_content() {
        let policy = minimal_exact_time_policy();
        assert_eq!(policy.policy_digest(), policy.clone().policy_digest());
        assert!(policy.policy_digest().starts_with("sha256:"));
        assert_eq!(policy.policy_digest().len(), 71);

        let edited = SchedulingPolicy {
            hold_policy: HoldPolicy {
                ttl_minutes: 6,
                ..policy.hold_policy.clone()
            },
            ..policy.clone()
        };
        assert_ne!(policy.policy_digest(), edited.policy_digest());
    }

    #[test]
    fn envelope_and_identity_findings_are_path_addressed() {
        let mut policy = minimal_exact_time_policy();
        policy.api_version = "registry.registrystack.org/other/v1".to_owned();
        policy.kind = "Other".to_owned();
        policy.scheduling.version = 0;
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"apiVersion: unsupported-api-version".to_owned()));
        assert!(rendered.contains(&"kind: unsupported-kind".to_owned()));
        assert!(rendered.contains(&"scheduling.version: invalid-bound".to_owned()));
    }

    #[test]
    fn mode_fields_must_match_the_declared_mode() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].exact_time = None;
        policy.offerings[0].arrival = Some(ArrivalOffering {
            window: "no-such-window".to_owned(),
            lead_time_minutes: 60,
            horizon_days: 45,
        });
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"offerings[0].exactTime: missing-mode-field".to_owned()));
        // The stray arrival block is refused as a whole; its window reference
        // is not validated because the block must be removed, not repaired.
        assert!(rendered.contains(&"offerings[0].arrival: wrong-mode-field".to_owned()));
    }

    #[test]
    fn references_into_missing_collections_are_named() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].service = "no-such-service".to_owned();
        policy.openings[0].holiday_set = "no-such-holidays".to_owned();
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"offerings[0].service: unknown-service".to_owned()));
        assert!(rendered.contains(&"openings[0].holidaySet: unknown-holiday-set".to_owned()));
    }

    #[test]
    fn every_arrival_offering_must_own_its_referenced_window() {
        let mut policy = household_window_policy();
        let windows = household_windows();
        let mut neighbour = policy.offerings[0].clone();
        neighbour.id = "household-afternoon".to_owned();
        policy.offerings.push(neighbour);

        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(ToString::to_string).collect();
        assert!(rendered.contains(&"offerings[1].arrival.window: mismatched-reference".to_owned()));
    }

    /// The weekly expansion serves at most MAXIMUM_PATTERN_SPAN_DAYS days, and
    /// the authoring check refuses a wider span at exactly that boundary, so a
    /// checked policy never deploys into a runtime that cannot expand it.
    #[test]
    fn an_opening_span_is_refused_only_past_the_calendar_boundary() {
        let base = chrono::NaiveDate::from_ymd_opt(2026, 1, 1).expect("a well-formed base date");
        let until = |days: u64| {
            base.checked_add_days(chrono::Days::new(days))
                .expect("a bounded span")
                .format("%Y-%m-%d")
                .to_string()
        };
        let mut policy = minimal_exact_time_policy();
        policy.openings[0].effective_from = base.format("%Y-%m-%d").to_string();
        policy.openings[0].effective_until = until(u64::from(
            registry_platform_calendar::MAXIMUM_PATTERN_SPAN_DAYS,
        ));
        assert!(policy.check().is_empty(), "{:?}", policy.check());

        policy.openings[0].effective_until =
            until(u64::from(registry_platform_calendar::MAXIMUM_PATTERN_SPAN_DAYS) + 1);
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"openings[0].effectiveUntil: pattern-span-too-large".to_owned()));
    }

    #[test]
    fn duplicate_ids_across_one_collection_are_rejected() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings.push(policy.offerings[0].clone());
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            rendered
                .iter()
                .filter(|f| f.ends_with("duplicate-identifier"))
                .count(),
            2
        );
    }

    /// Authored reminder offsets are part of the reviewed policy: a zero
    /// offset, a blank because, and two offsets at the same distance are all
    /// findings, and a well-formed schedule passes the check untouched.
    #[test]
    fn reminder_offsets_are_validated_like_every_authored_choice() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].reminders = vec![
            ReminderOffsetPolicy {
                minutes_before: 0,
                because: "   ".to_owned(),
            },
            ReminderOffsetPolicy {
                minutes_before: 1440,
                because: "One reminder the day before a counter update.".to_owned(),
            },
            ReminderOffsetPolicy {
                minutes_before: 1440,
                because: "A second reminder at the same distance.".to_owned(),
            },
        ];
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"offerings[0].reminders[0].minutesBefore: invalid-bound".to_owned())
        );
        assert!(rendered.contains(&"offerings[0].reminders[0].because: invalid-because".to_owned()));
        assert!(rendered
            .contains(&"offerings[0].reminders[2].minutesBefore: duplicate-identifier".to_owned()));

        policy.offerings[0].reminders.truncate(2);
        policy.offerings[0].reminders[0] = ReminderOffsetPolicy {
            minutes_before: 60,
            because: "One reminder an hour before.".to_owned(),
        };
        assert!(policy.check().is_empty(), "{:?}", policy.check());
    }

    #[test]
    fn subquota_slices_may_not_overdraw_the_window() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].subquotas[0].units = 3;
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"windows[0].subquotas: subquota-overdrawn".to_owned()));
    }

    #[test]
    fn window_units_must_fit_the_ledger_column() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].units = i32::MAX as u32;
        assert!(
            policy.check_window_records(&windows).is_empty(),
            "the largest ledger allocation must remain valid"
        );

        windows[0].units = i32::MAX as u32 + 1;
        let rendered: Vec<String> = policy
            .check_window_records(&windows)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(rendered, vec!["windows[0].units: invalid-bound".to_owned()]);
    }

    #[test]
    fn one_channel_may_not_hold_two_slices_of_one_window() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].subquotas[1].channel = Channel::Public;
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"windows[0].subquotas[1].channel: duplicate-identifier".to_owned())
        );
    }

    /// COR-3 / D5(a): a declared channel set is closed. A subquota may not
    /// reserve capacity for a channel the deployment does not say it serves,
    /// and a declaration naming one channel twice declares it once. An
    /// absent declaration declares nothing beyond the vocabulary.
    #[test]
    fn a_subquota_may_not_draw_on_an_undeclared_channel() {
        let mut policy = household_window_policy();
        let windows = household_windows();
        // The window serves public and assisted; the deployment declares
        // only assisted.
        policy.channels = vec![Channel::Assisted];
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"windows[0].subquotas[0].channel: unknown-channel".to_owned()),
            "{rendered:?}"
        );
        assert!(!rendered
            .iter()
            .any(|finding| finding.starts_with("windows[0].subquotas[1].channel:")));

        // With no declaration, the vocabulary alone governs and the same
        // subquotas check clean.
        policy.channels = Vec::new();
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered
                .iter()
                .all(|finding| !finding.ends_with("unknown-channel")),
            "{rendered:?}"
        );

        // A repeated declaration is a duplicate identifier.
        policy.channels = vec![Channel::Public, Channel::Public];
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"channels[1]: duplicate-identifier".to_owned()),
            "{rendered:?}"
        );
    }

    /// A resource pool and a published window anchor their capacity
    /// transactions on one row keyed by the identifier, so the two supply
    /// namespaces have to stay disjoint. The policy states one side of the
    /// collision by itself, and the records state the other, so each
    /// authored document is refused naming its own field.
    #[test]
    fn a_pool_and_a_window_may_not_share_one_supply_identifier() {
        let mut policy = household_window_policy();
        let windows = household_windows();
        assert!(policy.check().is_empty(), "{:?}", policy.check());
        assert!(
            policy.check_window_records(&windows).is_empty(),
            "{:?}",
            policy.check_window_records(&windows)
        );

        policy.offerings.push(OfferingPolicy {
            id: "urgent-five".to_owned(),
            service: "household-day".to_owned(),
            label: "Urgent five-minute slot".to_owned(),
            mode: SchedulingMode::ExactTime,
            location: "civic-hall".to_owned(),
            because: "Urgent matters get exact five-minute slots.".to_owned(),
            exact_time: Some(ExactTimeOffering {
                duration_minutes: 5,
                buffer_before_minutes: 0,
                buffer_after_minutes: 0,
                lead_time_minutes: 30,
                horizon_days: 14,
                pool: "household-morning-window".to_owned(),
                start_increment_minutes: 5,
                max_recipients: 1,
            }),
            arrival: None,
            cancellation_cutoff_minutes: 60,
            reminders: Vec::new(),
            duplicate_active_key: None,
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        });

        // The policy alone already names both sides: the arrival offering
        // points at a window identifier its own exact-time offering sells.
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(
            rendered
                .contains(&"offerings[0].arrival.window: supply-identifier-collision".to_owned()),
            "{rendered:?}"
        );

        // The published record is refused in its own vocabulary, which is
        // the finding the two database writes carry.
        let rendered: Vec<String> = policy
            .check_window_records(&windows)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(
            rendered.contains(&"windows[0].id: supply-identifier-collision".to_owned()),
            "{rendered:?}"
        );
    }

    /// AT-22, static half: an unpartitioned staffing claim over a pool that an
    /// exact-time offering also sells is rejected at publication.
    ///
    /// COR-8 widened the refusal to the mode mix itself: a window claim
    /// occupies the window's own supply while an exact-time claim occupies the
    /// member it books, so a pool backing both modes double-books the same
    /// staffing in a ledger that cannot see the conflict. No authored
    /// partition attributes the supply across the two modes, so the mix is
    /// refused whether the block declares one or not.
    #[test]
    fn an_unpartitioned_shared_staffing_block_is_rejected() {
        let mut policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].staffing = Some(WindowStaffing {
            pool: "officer-pool".to_owned(),
            reserved_members: None,
            because: "The morning block is staffed by the duty officers.".to_owned(),
        });
        policy.offerings.push(OfferingPolicy {
            id: "urgent-five".to_owned(),
            service: "household-day".to_owned(),
            label: "Urgent five-minute slot".to_owned(),
            mode: SchedulingMode::ExactTime,
            location: "civic-hall".to_owned(),
            because: "Urgent matters get exact five-minute slots.".to_owned(),
            exact_time: Some(ExactTimeOffering {
                duration_minutes: 5,
                buffer_before_minutes: 0,
                buffer_after_minutes: 0,
                lead_time_minutes: 30,
                horizon_days: 14,
                pool: "officer-pool".to_owned(),
                start_increment_minutes: 5,
                max_recipients: 1,
            }),
            arrival: None,
            cancellation_cutoff_minutes: 60,
            reminders: Vec::new(),
            duplicate_active_key: None,
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        });
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"windows[0].staffing.pool: shared-supply-unpartitioned".to_owned())
        );

        // A partition does not attribute the supply across modes, so the mix
        // is refused with the partition declared.
        windows[0].staffing = Some(WindowStaffing {
            pool: "officer-pool".to_owned(),
            reserved_members: Some(2),
            because: "Two of the four duty officers staff the block.".to_owned(),
        });
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(
            rendered.contains(&"windows[0].staffing.pool: shared-supply-unpartitioned".to_owned())
        );

        // A partitioned staffing block over a pool no exact-time offering
        // sells makes the share explicit and passes.
        windows[0].staffing = Some(WindowStaffing {
            pool: "hall-officers".to_owned(),
            reserved_members: Some(2),
            because: "Two of the four duty officers staff the block.".to_owned(),
        });
        assert!(
            policy.check_window_records(&windows).is_empty(),
            "{:?}",
            policy.check_window_records(&windows)
        );

        // A window with no staffing block draws on no pool at all, so it
        // carries no edge an exact-time pool could share: the mode mix a
        // staffing block would create cannot exist without one.
        windows[0].staffing = None;
        assert!(policy.check_window_records(&windows).is_empty());
    }

    #[test]
    fn overlapping_windows_may_not_share_a_staffing_pool() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].staffing = Some(WindowStaffing {
            pool: "officer-pool".to_owned(),
            reserved_members: None,
            because: "The morning block is staffed by the duty officers.".to_owned(),
        });
        windows.push(PublishedWindow {
            id: "household-noon-window".to_owned(),
            revision: 1,
            offering: "household-morning".to_owned(),
            location: "civic-hall".to_owned(),
            start: Utc.with_ymd_and_hms(2026, 10, 10, 9, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 10, 10, 11, 30, 0).unwrap(),
            units: 2,
            units_policy: RequiredUnitsPolicy::Fixed {
                units: 1,
                because: "One unit per party.".to_owned(),
            },
            subquotas: Vec::new(),
            leftover: None,
            staffing: Some(WindowStaffing {
                pool: "officer-pool".to_owned(),
                reserved_members: None,
                because: "The noon block claims the same officers.".to_owned(),
            }),
            because: "A second block in the same hall.".to_owned(),
        });
        // The second window's offering linkage is wrong on purpose in this
        // fixture; only the supply finding is asserted here.
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            rendered
                .iter()
                .filter(|finding| finding.ends_with("shared-supply-unpartitioned"))
                .count(),
            2
        );

        // A whole-pool claim and an attributed subset still have independent
        // window ledgers, so the authored subset cannot make the overlap safe.
        windows[1].staffing.as_mut().unwrap().reserved_members = Some(1);
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            rendered
                .iter()
                .filter(|finding| finding.ends_with("shared-supply-unpartitioned"))
                .count(),
            2
        );

        // Two attributed subsets are equally unenforceable: their claims lock
        // and consume separate window ids rather than a shared staffing slice.
        windows[0].staffing.as_mut().unwrap().reserved_members = Some(1);
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            rendered
                .iter()
                .filter(|finding| finding.ends_with("shared-supply-unpartitioned"))
                .count(),
            2
        );

        // Disjoint windows may reuse the pool regardless of their advisory
        // attributed member counts.
        let disjoint = PublishedWindow {
            start: Utc.with_ymd_and_hms(2026, 10, 10, 13, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 10, 10, 15, 0, 0).unwrap(),
            ..windows[1].clone()
        };
        windows[1] = disjoint;
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(!rendered
            .iter()
            .any(|f| f.ends_with("shared-supply-unpartitioned")));
    }

    /// AT-10, pure half: a normal reduction below standing commitments is
    /// rejected with the deficit, while a reduction that keeps commitments
    /// covered passes.
    #[test]
    fn a_reduction_below_standing_commitments_is_rejected_with_its_deficit() {
        let current = household_windows();
        let now = utc(6, 0);
        let claim = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some("public".to_owned()),
            start: utc(8, 0),
            end: utc(10, 0),
            units: 2,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![claim],
        };

        let mut reduced = current.clone();
        reduced[0].units = 1;
        assert_eq!(
            assess_window_record_impact(&current, &reduced, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: None,
                committed_units: 2,
                proposed_units: 1,
            }]
        );

        // Dropping the window entirely reduces both the total and the public
        // slice to zero; the total reduction is reported first.
        let mut removed = current.clone();
        removed.clear();
        let reductions = assess_window_record_impact(&current, &removed, &snapshot, now);
        assert_eq!(reductions[0].proposed_units, 0);
        assert_eq!(reductions[0].channel, None);

        // A reduction that still covers commitments, and an increase, pass.
        let mut adequate = current.clone();
        adequate[0].units = 2;
        assert!(assess_window_record_impact(&current, &adequate, &snapshot, now).is_empty());
        let mut increased = current.clone();
        increased[0].units = 9;
        assert!(assess_window_record_impact(&current, &increased, &snapshot, now).is_empty());
    }

    /// AT-10, channel half: a subquota reduced below its channel's standing
    /// commitments is rejected even when the window total is unchanged, and a
    /// dropped subquota proposes zero for its channel.
    #[test]
    fn a_subquota_reduction_strands_its_channel_even_at_an_unchanged_total() {
        let current = household_windows();
        let now = utc(6, 0);
        let claim = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some("public".to_owned()),
            start: utc(8, 0),
            end: utc(10, 0),
            units: 2,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![claim],
        };

        // The total stays at 3 while the public slice shrinks below the 2
        // units that channel already holds.
        let mut narrowed = current.clone();
        narrowed[0].subquotas[0].units = 1;
        assert_eq!(
            assess_window_record_impact(&current, &narrowed, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: Some(Channel::Public),
                committed_units: 2,
                proposed_units: 1,
            }]
        );

        // Dropping the subquota entirely is a reduction of that channel to
        // zero; only the channel strand is reported, the total still covers.
        let mut dropped = current.clone();
        dropped[0].subquotas.remove(0);
        assert_eq!(
            assess_window_record_impact(&current, &dropped, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: Some(Channel::Public),
                committed_units: 2,
                proposed_units: 0,
            }]
        );

        // A channel nothing has committed against never strands, and an
        // unchanged slice passes.
        let mut assisted_dropped = current.clone();
        assisted_dropped[0].subquotas.remove(1);
        assert!(
            assess_window_record_impact(&current, &assisted_dropped, &snapshot, now).is_empty()
        );
        let mut widened = current.clone();
        widened[0].subquotas[0].units = 2;
        assert!(assess_window_record_impact(&current, &widened, &snapshot, now).is_empty());
    }

    /// BL-2: a subquota that exists only in the proposal was never assessed,
    /// so a publication could add a channel slice below what that channel
    /// already holds and strand its commitments silently.
    #[test]
    fn an_added_subquota_never_strands_its_channel_at_publication() {
        let mut current = household_windows();
        current[0].subquotas.clear();
        let now = utc(6, 0);
        let claim = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some("public".to_owned()),
            start: utc(8, 0),
            end: utc(10, 0),
            units: 2,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![claim],
        };

        // Two public units already stand; the proposal publishes a public
        // slice of one for the first time.
        let mut proposal = current.clone();
        proposal[0].subquotas = vec![WindowSubquota {
            id: "public-quota".to_owned(),
            channel: Channel::Public,
            units: 1,
            because: "One public unit in the revised block.".to_owned(),
        }];
        assert_eq!(
            assess_window_record_impact(&current, &proposal, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: Some(Channel::Public),
                committed_units: 2,
                proposed_units: 1,
            }]
        );

        // A slice that still covers what the channel holds passes.
        let mut covered = current.clone();
        covered[0].subquotas = vec![WindowSubquota {
            id: "public-quota".to_owned(),
            channel: Channel::Public,
            units: 2,
            because: "Two public units in the revised block.".to_owned(),
        }];
        assert!(assess_window_record_impact(&current, &covered, &snapshot, now).is_empty());
    }

    /// BL-3: a window moved under the same id was assessed by supply id
    /// alone, so a proposal could move every standing commitment out of its
    /// window and pass as safe. Each standing claim's interval is now
    /// compared against the proposed window's interval.
    #[test]
    fn moving_a_published_window_reports_the_stranded_commitments() {
        let current = household_windows();
        let now = utc(6, 0);
        let claim = LedgerClaim {
            id: "claim-1".to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some("public".to_owned()),
            start: utc(8, 0),
            end: utc(10, 0),
            units: 2,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![claim.clone()],
        };

        // The window moves two months under the same id; the two standing
        // units fall outside the published interval and are stranded against
        // the zero capacity that proposal leaves where they stand.
        let mut moved = current.clone();
        moved[0].start = Utc.with_ymd_and_hms(2026, 12, 24, 8, 0, 0).unwrap();
        moved[0].end = Utc.with_ymd_and_hms(2026, 12, 24, 10, 0, 0).unwrap();
        assert_eq!(
            assess_window_record_impact(&current, &moved, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: None,
                committed_units: 2,
                proposed_units: 0,
            }]
        );

        // A shortened interval strands only the claims it no longer covers:
        // the morning claim remains fully inside, while the late one only
        // partly overlaps and therefore cannot be treated as covered.
        let covered = LedgerClaim {
            end: utc(9, 0),
            ..claim
        };
        let late = LedgerClaim {
            id: "claim-2".to_owned(),
            offering: "household-renewal".to_owned(),
            supply_id: "household-morning-window".to_owned(),
            kind: LedgerKind::Booking,
            channel: Some("assisted".to_owned()),
            start: utc(9, 30),
            end: utc(10, 0),
            units: 1,
            duplicate_key: None,
            expires_at: None,
        };
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![covered, late],
        };
        let mut shortened = current.clone();
        shortened[0].end = utc(9, 45);
        assert_eq!(
            assess_window_record_impact(&current, &shortened, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: None,
                committed_units: 1,
                proposed_units: 0,
            }]
        );

        // A window that stays put reports nothing: its claims still meet it.
        assert!(assess_window_record_impact(&current, &current.clone(), &snapshot, now).is_empty());
    }

    #[test]
    fn standing_claims_are_guarded_when_the_current_window_record_is_missing() {
        let proposed = household_windows();
        let now = utc(6, 0);
        let snapshot = crate::model::LedgerSnapshot {
            claims: vec![LedgerClaim {
                id: "claim-1".to_owned(),
                offering: "household-renewal".to_owned(),
                supply_id: "household-morning-window".to_owned(),
                kind: LedgerKind::Booking,
                channel: Some("public".to_owned()),
                start: utc(8, 0),
                end: utc(10, 0),
                units: 2,
                duplicate_key: None,
                expires_at: None,
            }],
        };

        assert!(assess_window_record_impact(&[], &proposed, &snapshot, now).is_empty());

        let mut inadequate = proposed.clone();
        inadequate[0].units = 1;
        assert_eq!(
            assess_window_record_impact(&[], &inadequate, &snapshot, now),
            vec![CapacityReduction {
                window: "household-morning-window".to_owned(),
                channel: None,
                committed_units: 2,
                proposed_units: 1,
            }]
        );
    }

    #[test]
    fn scheduling_observer_hooks_accept_only_the_closed_runtime_contract() {
        let mut policy = minimal_exact_time_policy();
        policy.hooks = vec![serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "after",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "url", "destinationId": "appointment-events"},
        }))
        .expect("the shared declaration shape parses")];
        assert!(policy.check().is_empty());

        policy.hooks[0] = serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "after",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "wasm", "module": "observer.wasm", "abi": "vendor.hook/v9"},
        }))
        .expect("the declaration shape parses before semantic validation");
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"hooks[0].handler.abi: unsupported-hook-abi".to_owned()));

        policy.hooks[0] = serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "before",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "url", "destinationId": "appointment-events"},
        }))
        .expect("the declaration shape parses before semantic validation");
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(rendered.contains(&"hooks[0].phase: unsupported-hook-phase".to_owned()));

        policy.hooks[0] = serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "after",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "rhai", "script": "observer.rhai"},
        }))
        .expect("the declaration shape parses before semantic validation");
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(rendered.contains(&"hooks[0].handler.abi: unsupported-hook-abi".to_owned()));

        policy.hooks[0] = serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "after",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "url", "destinationId": "https://receiver.example"},
        }))
        .expect("the declaration shape parses before product validation");
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(rendered
            .contains(&"hooks[0].handler.destinationId: invalid-hook-destination".to_owned()));

        policy.hooks[0] = serde_json::from_value(serde_json::json!({
            "id": "appointment-observer",
            "phase": "after",
            "trigger": "appointment.confirmed",
            "projection": [],
            "handler": {"kind": "url", "destinationId": "appointment-events"},
        }))
        .expect("the shared declaration shape parses");
        policy.hooks.push(policy.hooks[0].clone());
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(rendered.contains(&"hooks[1].id: duplicate-identifier".to_owned()));

        for (member, value, expected) in [
            (
                "trigger",
                serde_json::json!("hold.expired"),
                "hooks[0].trigger: unsupported-hook-trigger",
            ),
            (
                "when",
                serde_json::json!({"state": "active"}),
                "hooks[0].when: unsupported-hook-condition",
            ),
            (
                "principal",
                serde_json::json!("scheduling-hook"),
                "hooks[0].principal: unsupported-hook-principal",
            ),
            (
                "projection",
                serde_json::json!(["actor"]),
                "hooks[0].projection: unsupported-hook-projection",
            ),
        ] {
            let mut declaration = serde_json::json!({
                "id": "appointment-observer",
                "phase": "after",
                "trigger": "appointment.confirmed",
                "projection": [],
                "handler": {"kind": "url", "destinationId": "appointment-events"},
            });
            declaration[member] = value;
            policy.hooks = vec![serde_json::from_value(declaration).expect("the shape parses")];
            let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
            assert!(rendered.contains(&expected.to_owned()), "{rendered:?}");
        }

        policy.hooks = vec![serde_json::from_value(serde_json::json!({
            "id": "cancellation-observer",
            "phase": "after",
            "trigger": "appointment.cancelled",
            "projection": ["reason"],
            "handler": {"kind": "url", "destinationId": "appointment-events"},
        }))
        .expect("the shared declaration shape parses")];
        let rendered: Vec<String> = policy.check().iter().map(ToString::to_string).collect();
        assert!(rendered.contains(&"hooks[0].projection: unsupported-hook-projection".to_owned()));
    }

    #[test]
    fn legacy_duplicate_and_mismatched_hook_members_are_refused_by_the_shared_shape() {
        let base =
            serde_norway::to_string(&minimal_exact_time_policy()).expect("the fixture serializes");
        for hooks in [
            "hooks:\n- id: observer\n  abi: registry.scheduling-hook/v1\n  because: legacy",
            "hooks:\n- id: observer\n  phase: after\n  phase: before\n  trigger: appointment.confirmed\n  projection: []\n  handler:\n    kind: url\n    destinationId: appointment-events",
            "hooks:\n- id: observer\n  phase: after\n  trigger: appointment.confirmed\n  projection: []\n  handler:\n    kind: wasm\n    script: observer.rhai\n    abi: registry.hook-handler/v1",
        ] {
            let yaml = base.replace("hooks: []", hooks);
            assert!(parse_policy_yaml(&yaml).is_err(), "accepted:\n{hooks}");
        }
    }

    #[test]
    fn a_declared_leftover_policy_is_refused_because_nothing_reads_it() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        assert!(policy.check_window_records(&windows).is_empty());

        windows[0].leftover = Some(LeftoverCapacityPolicy::BecomesWalkIn);
        let findings = policy.check_window_records(&windows);
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"windows[0].leftover: leftover-unsupported".to_owned()));
    }

    #[test]
    fn identifiers_dates_and_times_follow_their_grammars() {
        assert!(valid_identifier("north-counter-2"));
        assert!(!valid_identifier("North"));
        assert!(!valid_identifier("north counter"));
        assert!(!valid_identifier(""));
        assert!(!valid_identifier(&"x".repeat(65)));
        assert!(valid_hh_mm("09:00"));
        assert!(!valid_hh_mm("9:00"));
        assert!(!valid_hh_mm("24:00"));
        assert!(valid_iso_date("2026-10-05"));
        assert!(!valid_iso_date("2026-10-5"));
        assert!(!valid_iso_date("2026-02-30"));
    }

    /// A value whose text is outside its grammar is not an unfinished
    /// project: no addition turns `9:00 AM` into a clock, only a correction.
    /// The reason says so, and it names the field that is actually malformed,
    /// so adopter tooling can refuse the document instead of reporting it as
    /// incomplete authoring. A well-formed value that breaks its range stays
    /// an invalid bound: the text parses, the range does not hold.
    #[test]
    fn a_clock_or_date_outside_its_grammar_is_malformed_rather_than_unbounded() {
        let rendered = |policy: &SchedulingPolicy| -> Vec<String> {
            policy.check().iter().map(ToString::to_string).collect()
        };

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].start_time = "9:00 AM".to_owned();
        assert_eq!(
            rendered(&policy),
            ["openings[0].startTime: malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].end_time = "12.30".to_owned();
        assert_eq!(rendered(&policy), ["openings[0].endTime: malformed-value"]);

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].effective_from = "01/10/2026".to_owned();
        assert_eq!(
            rendered(&policy),
            ["openings[0].effectiveFrom: malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.holiday_sets[0].dates[0] = "25 December 2026".to_owned();
        assert_eq!(
            rendered(&policy),
            ["holidaySets[0].dates[0]: malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].end_time = "08:00".to_owned();
        assert_eq!(rendered(&policy), ["openings[0].endTime: invalid-bound"]);

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].effective_until = "2026-09-30".to_owned();
        assert_eq!(
            rendered(&policy),
            ["openings[0].effectiveUntil: invalid-bound"]
        );
    }

    #[test]
    fn weekdays_and_channels_serialize_in_their_published_spelling() {
        assert_eq!(
            serde_norway::to_string(&PolicyWeekday::Wed).unwrap(),
            "wed\n"
        );
        assert_eq!(
            serde_norway::from_str::<PolicyWeekday>("wed").unwrap(),
            PolicyWeekday::Wed
        );
        assert_eq!(Channel::WalkIn.as_str(), "walk-in");
        assert_eq!(
            serde_norway::from_str::<Channel>("walk-in").unwrap(),
            Channel::WalkIn
        );
        assert_eq!(PolicyWeekday::Sun.to_chrono(), chrono::Weekday::Sun);
    }

    #[test]
    fn party_counts_still_parse_from_the_policy_surface() {
        let party = PartyCounts {
            recipients: 2,
            attendees: 3,
        };
        assert_eq!(
            serde_json::to_value(party).unwrap(),
            serde_json::json!({"recipients": 2, "attendees": 3})
        );
    }

    #[test]
    fn unknown_policy_fields_are_refused() {
        let yaml = r#"
apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: broken
  version: 1
services: []
offerings: []
holidaySets: []
openings: []
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short.
surprise: true
"#;
        assert!(parse_policy_yaml(yaml).is_err());
    }

    #[test]
    fn collection_bounds_are_enforced() {
        let mut policy = minimal_exact_time_policy();
        policy.services = (0..MAXIMUM_COLLECTION_ENTRIES + 1)
            .map(|index| ServicePolicy {
                id: format!("service-{index}"),
                label: "Filler service".to_owned(),
            })
            .collect();
        let findings = policy.check();
        let rendered: Vec<String> = findings.iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"services: invalid-bound".to_owned()));

        let at_bound = minimal_exact_time_policy();
        assert!(at_bound.check().is_empty());
    }

    /// An offering may require no more capabilities or prerequisites than a
    /// request is allowed to carry. Past that bound the offering publishes
    /// cleanly and no admissible request can ever satisfy it, so the refusal
    /// belongs at authoring time where the operator can still name it.
    #[test]
    fn offering_requirement_collections_are_bounded() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].requires_capabilities = (0..=MAXIMUM_COLLECTION_ENTRIES)
            .map(|index| format!("capability-{index}"))
            .collect();
        policy.offerings[0].prerequisites = (0..=MAXIMUM_COLLECTION_ENTRIES)
            .map(|index| format!("urn:evidence:residency-{index}"))
            .collect();
        let rendered: Vec<String> = policy.check().iter().map(|f| f.to_string()).collect();
        assert!(rendered.contains(&"offerings[0].requiresCapabilities: invalid-bound".to_owned()));
        assert!(rendered.contains(&"offerings[0].prerequisites: invalid-bound".to_owned()));

        let mut at_bound = minimal_exact_time_policy();
        at_bound.offerings[0].requires_capabilities = (1..=MAXIMUM_COLLECTION_ENTRIES)
            .map(|index| format!("capability-{index}"))
            .collect();
        at_bound.offerings[0].prerequisites = (1..=MAXIMUM_COLLECTION_ENTRIES)
            .map(|index| format!("urn:evidence:residency-{index}"))
            .collect();
        assert!(at_bound.check().is_empty());
    }
}
