// SPDX-License-Identifier: Apache-2.0

//! The authored scheduling project: services, offerings, opening patterns,
//! holiday sets, and the hold policy, with the validators a publication gate
//! runs. Published arrival-window supply is an operator record referenced by
//! identifier from an arrival offering.
//!
//! The project is layer one of the configuration model. It declares what a
//! deployment publishes and why; locations, resource pools, arrival windows,
//! and dated exceptions are runtime records the project references by
//! identifier but never embeds, so the same published project governs every
//! environment that resolves those identifiers.

use chrono::{DateTime, Utc};
use registry_platform_hooks::{validate_hooks, HookDeclaration, HookHandlerSource, HookPhase};
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, ProjectIdentity, Reader, RemovedKey,
    Report, RetiredApiVersion,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::diagnostics::{findings_report, FindingArea, PolicyCheckReason, SchedulingDiagnostic};
use crate::naming::{
    RETIRED_SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_KIND,
};
use crate::typed::{
    MAXIMUM_HORIZON_DAYS, MAXIMUM_HORIZON_MINUTES, MAXIMUM_POOL_MEMBERS, MAXIMUM_REVISION,
    MAXIMUM_UNITS, MINUTES_PER_DAY,
};
use crate::units::{check_because, RequiredUnitsPolicy};

/// The maximum number of entries one policy collection may carry.
pub const MAXIMUM_COLLECTION_ENTRIES: usize = 256;

/// The maximum bytes of a human-facing label.
pub const MAXIMUM_LABEL_BYTES: usize = 128;

/// The format a `scheduling.yaml` file declares (CFG-ENV-1).
pub const SCHEDULING_PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: SCHEDULING_POLICY_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(SCHEDULING_POLICY_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: RETIRED_SCHEDULING_POLICY_API_VERSION,
            replacement:
                "Write apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1 \
                          and kind: SchedulingProject, and move the scheduling block to project.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/scheduling",
            replacement: "Write the identity under project, with id and a text version such as \
                          2026.1.",
        },
        RemovedKey {
            pointer: "/offerings/*/exactTime/maxRecipients",
            replacement: "Write maximumRecipients.",
        },
        RemovedKey {
            pointer: "/offerings/*/reminders/*/minutesBefore",
            replacement: "Write offsetMinutes.",
        },
        RemovedKey {
            pointer: "/holdPolicy/maxPerCaller",
            replacement: "Write maximumPerCaller.",
        },
        RemovedKey {
            pointer: "/hooks/*/handler/kind",
            replacement: "Write type: url.",
        },
    ],
};

/// One weekday of an opening pattern.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// A service a deployment schedules.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicePolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub label: String,
}

/// How an offering delivers its service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SchedulingMode {
    ExactTime,
    ArrivalWindow,
}

/// The exact-time block of an offering: appointment length, protections, and
/// the interchangeable pool that backs it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTimeOffering {
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MINUTES_PER_DAY>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MINUTES_PER_DAY>")
    )]
    pub duration_minutes: u32,
    /// Setup time occupied before the displayed start.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 0, MINUTES_PER_DAY>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MINUTES_PER_DAY>")
    )]
    pub buffer_before_minutes: u32,
    /// Cleanup time occupied after the displayed end.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 0, MINUTES_PER_DAY>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MINUTES_PER_DAY>")
    )]
    pub buffer_after_minutes: u32,
    /// The earliest lead time a caller may book at.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_HORIZON_MINUTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_HORIZON_MINUTES>")
    )]
    pub lead_time_minutes: u32,
    /// How far ahead booking is open.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_HORIZON_DAYS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_HORIZON_DAYS>")
    )]
    pub horizon_days: u32,
    /// The pool of interchangeable members backing this offering. A pool is
    /// its members, never an independent counter.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub pool: String,
    /// The grid displayed starts must land on.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MINUTES_PER_DAY>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MINUTES_PER_DAY>")
    )]
    pub start_increment_minutes: u32,
    /// The largest party the offering serves.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
    )]
    pub maximum_recipients: u32,
}

/// The arrival-window block of an offering.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrivalOffering {
    /// The published window this offering serves arrivals in.
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub window: String,
    /// The earliest lead time a caller may book the window at.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_HORIZON_MINUTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_HORIZON_MINUTES>")
    )]
    pub lead_time_minutes: u32,
    /// How far ahead of the window's start booking is open.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_HORIZON_DAYS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_HORIZON_DAYS>")
    )]
    pub horizon_days: u32,
}

/// One authored reminder offset: a notification intent becomes due this many
/// minutes before the displayed start of an appointment on the offering.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderOffsetPolicy {
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_HORIZON_MINUTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_HORIZON_MINUTES>")
    )]
    pub offset_minutes: u32,
    pub because: String,
}

/// One bookable thing a deployment offers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferingPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub service: String,
    pub label: String,
    pub mode: SchedulingMode,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub location: String,
    pub because: String,
    /// Present exactly when `mode` is `exact-time`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_time: Option<ExactTimeOffering>,
    /// Present exactly when `mode` is `arrival-window`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrival: Option<ArrivalOffering>,
    /// How late before the displayed start a booking may still be cancelled.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 0, MAXIMUM_HORIZON_MINUTES>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MAXIMUM_HORIZON_MINUTES>")
    )]
    pub cancellation_cutoff_minutes: u32,
    /// Authored reminder offsets for this offering. The runtime mints one
    /// revision-bound intent per offset whose due time is still ahead when
    /// the appointment commits; message transport stays external (INT-02).
    /// An offering with no reminders omits the member or lists none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub reminders: Vec<ReminderOffsetPolicy>,
    /// The caller attribute an active-booking duplicate check keys on, when
    /// the service defines one. Phone numbers and email addresses are never
    /// valid duplicate keys.
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_local_id",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::LocalId>")
    )]
    pub duplicate_active_key: Option<String>,
    /// Capabilities every backing member must have for this offering. An
    /// offering that requires none omits the member.
    #[serde(
        default,
        deserialize_with = "crate::typed::non_empty_unique_local_ids",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>",
            length(min = 1, max = 256)
        )
    )]
    pub requires_capabilities: Vec<String>,
    /// Prerequisite references a requesting party must hold. An offering
    /// with no prerequisite omits the member.
    #[serde(
        default,
        deserialize_with = "crate::typed::non_empty_unique_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<String>",
            length(min = 1, max = 256)
        )
    )]
    pub prerequisites: Vec<String>,
}

/// A bounded weekly opening pattern over local wall-clock time. The timezone
/// comes from the location record the pattern references.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpeningPatternPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub location: String,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub holiday_set: String,
    #[serde(deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<PolicyWeekday>",
            length(min = 1)
        )
    )]
    pub weekdays: Vec<PolicyWeekday>,
    pub start_time: String,
    pub end_time: String,
    pub effective_from: String,
    pub effective_until: String,
    pub because: String,
}

/// A named, revisioned set of holiday dates.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "crate::typed::bounded_u64::<_, 1, MAXIMUM_REVISION>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, MAXIMUM_REVISION>")
    )]
    pub revision: u64,
    pub because: String,
    /// The dates the set closes. A set that closes no date omits the member.
    #[serde(
        default,
        deserialize_with = "crate::typed::non_empty_unique_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<String>",
            length(min = 1, max = 256)
        )
    )]
    pub dates: Vec<String>,
}

/// The authenticated channel a subquota limits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowSubquota {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub channel: Channel,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
    )]
    pub units: u32,
    pub because: String,
}

/// What a window says happens to its leftover capacity when it closes. The
/// declaration names an intent; this version of the runtime reads none of
/// it, so `check` refuses a window that declares one rather than accept a
/// promise nothing keeps. There is no default and no borrowing from the
/// next window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowStaffing {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub pool: String,
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_bounded_u32::<_, 1, MAXIMUM_POOL_MEMBERS>",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::BoundedU32<1, MAXIMUM_POOL_MEMBERS>>")
    )]
    pub reserved_members: Option<u32>,
    pub because: String,
}

/// A published arrival window with its capacity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishedWindow {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "crate::typed::bounded_u64::<_, 1, MAXIMUM_REVISION>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<1, MAXIMUM_REVISION>")
    )]
    pub revision: u64,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub offering: String,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub location: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Published capacity in the unit basis the units policy defines.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
    )]
    pub units: u32,
    pub units_policy: RequiredUnitsPolicy,
    /// Per-channel ceilings within `units`. A window that limits no channel
    /// omits the member.
    #[serde(
        default,
        deserialize_with = "crate::typed::non_empty_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 4)))]
    pub subquotas: Vec<WindowSubquota>,
    /// Declared intent for the window's leftover capacity. Nothing reads it
    /// in this version, so a declaration is refused at authoring; the field
    /// stays so a refusal can name it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leftover: Option<LeftoverCapacityPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staffing: Option<WindowStaffing>,
    pub because: String,
}

/// The hold policy every offering inherits.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldPolicy {
    /// How long a hold keeps its capacity: at most one day.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MINUTES_PER_DAY>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MINUTES_PER_DAY>")
    )]
    pub ttl_minutes: u32,
    /// The most live holds one caller may keep at once.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_UNITS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_UNITS>")
    )]
    pub maximum_per_caller: u32,
    pub because: String,
}

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

/// When an observer hook runs. Scheduling runs every hook after the
/// appointment transaction commits, never inside its capacity transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ObserverPhase {
    After,
}

/// The appointment lifecycle transition an observer hook follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ObserverTrigger {
    #[serde(rename = "appointment.confirmed")]
    AppointmentConfirmed,
    #[serde(rename = "appointment.rescheduled")]
    AppointmentRescheduled,
    #[serde(rename = "appointment.cancelled")]
    AppointmentCancelled,
}

impl ObserverTrigger {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppointmentConfirmed => APPOINTMENT_CONFIRMED_TRIGGER,
            Self::AppointmentRescheduled => APPOINTMENT_RESCHEDULED_TRIGGER,
            Self::AppointmentCancelled => APPOINTMENT_CANCELLED_TRIGGER,
        }
    }

    /// The closed projection this trigger publishes to an observer.
    const fn projection_fields(self) -> &'static [&'static str] {
        match self {
            Self::AppointmentConfirmed | Self::AppointmentRescheduled => {
                APPOINTMENT_OBSERVER_FIELDS
            }
            Self::AppointmentCancelled => CANCELLATION_OBSERVER_FIELDS,
        }
    }
}

/// Where an observer hook delivers, chosen by its `type` member. Scheduling
/// delivers to a URL destination the runtime configuration binds, and to
/// nothing else.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum ObserverHandler {
    Url {
        #[serde(deserialize_with = "crate::typed::local_id")]
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        destination_id: String,
    },
}
registry_platform_yaml::tagged_union!(ObserverHandler);

/// The serialized form of [`ObserverHandler`].
#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ObserverHandlerWire<'a> {
    Url { destination_id: &'a str },
}

impl Serialize for ObserverHandler {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Url { destination_id } => ObserverHandlerWire::Url { destination_id },
        }
        .serialize(serializer)
    }
}

/// One observer hook: the shared Registry Stack hook declaration narrowed to
/// the closed Scheduling contract. It runs after commit, follows one of three
/// appointment lifecycle triggers, delivers to a URL destination, and takes
/// no condition and no proposal principal.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub phase: ObserverPhase,
    pub trigger: ObserverTrigger,
    /// The fields of the trigger's closed projection the observer receives.
    /// A hook that needs none lists none.
    #[serde(deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<String>")
    )]
    pub projection: Vec<String>,
    pub handler: ObserverHandler,
}

impl HookPolicy {
    /// The shared declaration the hook runtime reads.
    #[must_use]
    pub fn declaration(&self) -> HookDeclaration {
        let ObserverHandler::Url { destination_id } = &self.handler;
        HookDeclaration {
            id: self.id.clone(),
            phase: match self.phase {
                ObserverPhase::After => HookPhase::After,
            },
            trigger: self.trigger.as_str().to_owned(),
            when: None,
            principal: None,
            projection: self.projection.iter().cloned().collect(),
            handler: HookHandlerSource::Url {
                destination_id: destination_id.clone(),
            },
        }
    }
}

/// The authored scheduling project, `scheduling.yaml`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingPolicy {
    pub api_version: String,
    pub kind: String,
    pub project: ProjectIdentity,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub services: Vec<ServicePolicy>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub offerings: Vec<OfferingPolicy>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub holiday_sets: Vec<HolidaySetPolicy>,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub openings: Vec<OpeningPatternPolicy>,
    /// The channels this deployment serves. The vocabulary is closed by the
    /// `Channel` type itself; the declaration narrows it to the served
    /// subset, every subquota must draw on a declared channel, and a request
    /// naming anything else is refused. The set is required and holds at
    /// least one channel: a deployment that names none serves none.
    #[serde(deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<Channel>", length(min = 1))
    )]
    pub channels: Vec<Channel>,
    pub hold_policy: HoldPolicy,
    /// Observer hooks. A project with none omits the member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub hooks: Vec<HookPolicy>,
}

impl SchedulingPolicy {
    /// Read one `scheduling.yaml` file through the shared reader, without
    /// its semantic checks. `file` is the name diagnostics carry. A refusal
    /// is the report a check command prints unchanged.
    pub fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = registry_platform_config::AuthoredExpressions;
        Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&SCHEDULING_PROJECT_FORMAT))
    }

    /// Read and check one `scheduling.yaml` file: every structural problem,
    /// or every finding of [`SchedulingPolicy::check`], each at its position.
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let decoded = Self::decode(file, bytes)?;
        let findings = decoded.value.check();
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(findings_report(&decoded.document, &findings))
        }
    }

    #[must_use]
    pub fn offering(&self, id: &str) -> Option<&OfferingPolicy> {
        self.offerings.iter().find(|offering| offering.id == id)
    }

    #[must_use]
    pub fn holiday_set(&self, id: &str) -> Option<&HolidaySetPolicy> {
        self.holiday_sets.iter().find(|set| set.id == id)
    }

    /// The shared declarations of the project's observer hooks, in
    /// declaration order.
    #[must_use]
    pub fn hook_declarations(&self) -> Vec<HookDeclaration> {
        self.hooks.iter().map(HookPolicy::declaration).collect()
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

    /// Check the whole project. Every finding names the RFC 6901 pointer that
    /// failed. The reader already refuses a value outside its type, so these
    /// checks cover the rules that span members, and a project built in code.
    pub fn check(&self) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        if self.api_version != SCHEDULING_POLICY_API_VERSION {
            findings.push(SchedulingDiagnostic::new(
                "/apiVersion",
                PolicyCheckReason::UnsupportedApiVersion,
            ));
        }
        if self.kind != SCHEDULING_POLICY_KIND {
            findings.push(SchedulingDiagnostic::new(
                "/kind",
                PolicyCheckReason::UnsupportedKind,
            ));
        }
        if self.project.version.trim().is_empty() {
            findings.push(SchedulingDiagnostic::new(
                "/project/version",
                PolicyCheckReason::EmptyText,
            ));
        }

        check_collection_non_empty(&self.services, "/services", &mut findings);
        check_collection_non_empty(&self.offerings, "/offerings", &mut findings);
        check_collection_non_empty(&self.holiday_sets, "/holidaySets", &mut findings);
        check_collection_non_empty(&self.openings, "/openings", &mut findings);
        check_collection_non_empty(&self.channels, "/channels", &mut findings);
        check_collection_bound(&self.services, "/services", &mut findings);
        check_collection_bound(&self.offerings, "/offerings", &mut findings);
        check_collection_bound(&self.holiday_sets, "/holidaySets", &mut findings);
        check_collection_bound(&self.openings, "/openings", &mut findings);

        // The channel set is a closed list of the channels this deployment
        // serves; naming one twice declares it once.
        let mut declared_channels: Vec<Channel> = Vec::new();
        for (index, channel) in self.channels.iter().enumerate() {
            if declared_channels.contains(channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("/channels/{index}"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            declared_channels.push(*channel);
        }

        let mut service_ids = Vec::new();
        for (index, service) in self.services.iter().enumerate() {
            let path = format!("/services/{index}");
            check_identifier(&service.id, &format!("{path}/id"), &mut findings);
            check_label(&service.label, &format!("{path}/label"), &mut findings);
            push_unique(&mut service_ids, &service.id, &path, &mut findings);
        }

        for (index, set) in self.holiday_sets.iter().enumerate() {
            let path = format!("/holidaySets/{index}");
            // A holiday set with no dates is complete: it observes none.
            if set.revision == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}/revision"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            check_because(&set.because, &format!("{path}/because"), &mut findings);
            check_identifier(&set.id, &format!("{path}/id"), &mut findings);
            check_collection_bound(&set.dates, &format!("{path}/dates"), &mut findings);
            for (date_index, date) in set.dates.iter().enumerate() {
                if !valid_iso_date(date) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}/dates/{date_index}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            self.check_unique_id(&set.id, &path, Collection::HolidaySets, &mut findings);
        }

        for (index, opening) in self.openings.iter().enumerate() {
            let path = format!("/openings/{index}");
            check_identifier(&opening.id, &format!("{path}/id"), &mut findings);
            check_identifier(
                &opening.location,
                &format!("{path}/location"),
                &mut findings,
            );
            if self.holiday_set(&opening.holiday_set).is_none() {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}/holidaySet"),
                    PolicyCheckReason::UnknownHolidaySet,
                ));
            }
            check_collection_non_empty(
                &opening.weekdays,
                &format!("{path}/weekdays"),
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
                        format!("{path}/{field}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            let clocks_are_clocks =
                valid_hh_mm(&opening.start_time) && valid_hh_mm(&opening.end_time);
            if clocks_are_clocks && opening.start_time >= opening.end_time {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}/endTime"),
                    PolicyCheckReason::InvertedRange,
                ));
            }
            for (field, value) in [
                ("effectiveFrom", &opening.effective_from),
                ("effectiveUntil", &opening.effective_until),
            ] {
                if !valid_iso_date(value) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}/{field}"),
                        PolicyCheckReason::MalformedValue,
                    ));
                }
            }
            let dates_are_dates =
                valid_iso_date(&opening.effective_from) && valid_iso_date(&opening.effective_until);
            if dates_are_dates && opening.effective_from > opening.effective_until {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}/effectiveUntil"),
                    PolicyCheckReason::InvertedRange,
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
                        format!("{path}/effectiveUntil"),
                        PolicyCheckReason::PatternSpanTooLarge,
                    ));
                }
            }
            check_because(&opening.because, &format!("{path}/because"), &mut findings);
            self.check_unique_id(&opening.id, &path, Collection::Openings, &mut findings);
        }

        for (index, offering) in self.offerings.iter().enumerate() {
            self.check_offering(offering, index, &mut findings);
        }
        for (index, offering) in self.offerings.iter().enumerate() {
            if let Some(arrival) = &offering.arrival {
                if self.sells_pool(&arrival.window) {
                    findings.push(SchedulingDiagnostic::new(
                        format!("/offerings/{index}/arrival/window"),
                        PolicyCheckReason::SupplyIdentifierCollision,
                    ));
                }
            }
        }

        check_because(
            &self.hold_policy.because,
            "/holdPolicy/because",
            &mut findings,
        );
        if self.hold_policy.ttl_minutes == 0 {
            findings.push(SchedulingDiagnostic::new(
                "/holdPolicy/ttlMinutes",
                PolicyCheckReason::InvalidBound,
            ));
        }
        if self.hold_policy.maximum_per_caller == 0 {
            findings.push(SchedulingDiagnostic::new(
                "/holdPolicy/maximumPerCaller",
                PolicyCheckReason::InvalidBound,
            ));
        }

        check_collection_bound(&self.hooks, "/hooks", &mut findings);
        let mut hook_ids = Vec::new();
        for (index, hook) in self.hooks.iter().enumerate() {
            let path = format!("/hooks/{index}");
            check_identifier(&hook.id, &format!("{path}/id"), &mut findings);
            push_unique(&mut hook_ids, &hook.id, &path, &mut findings);
            check_scheduling_hook(hook, &path, &mut findings);
        }
        // Every shared rule a Scheduling hook can break is already named
        // above at its own member; the shared validator stays the backstop.
        if hook_ids.len() == self.hooks.len() && validate_hooks(&self.hook_declarations()).is_err()
        {
            findings.push(SchedulingDiagnostic::new(
                "/hooks",
                PolicyCheckReason::InvalidHookDeclaration,
            ));
        }

        findings
    }

    fn check_offering(
        &self,
        offering: &OfferingPolicy,
        index: usize,
        findings: &mut Vec<SchedulingDiagnostic>,
    ) {
        let path = format!("/offerings/{index}");
        check_identifier(&offering.id, &format!("{path}/id"), findings);
        check_identifier(&offering.service, &format!("{path}/service"), findings);
        if !service_ids_contains(self, &offering.service) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/service"),
                PolicyCheckReason::UnknownService,
            ));
        }
        check_identifier(&offering.location, &format!("{path}/location"), findings);
        check_label(&offering.label, &format!("{path}/label"), findings);
        check_because(&offering.because, &format!("{path}/because"), findings);
        self.check_unique_id(&offering.id, &path, Collection::Offerings, findings);

        let (block, block_member) = match offering.mode {
            SchedulingMode::ExactTime => (offering.exact_time.is_some(), "exactTime"),
            SchedulingMode::ArrivalWindow => (offering.arrival.is_some(), "arrival"),
        };
        if !block {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/{block_member}"),
                PolicyCheckReason::MissingModeField,
            ));
        }
        match offering.mode {
            SchedulingMode::ExactTime => {
                if offering.arrival.is_some() {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}/arrival"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
                if let Some(exact) = &offering.exact_time {
                    let block_path = format!("{path}/exactTime");
                    for (member, value) in [
                        ("durationMinutes", exact.duration_minutes),
                        ("leadTimeMinutes", exact.lead_time_minutes),
                        ("horizonDays", exact.horizon_days),
                        ("startIncrementMinutes", exact.start_increment_minutes),
                        ("maximumRecipients", exact.maximum_recipients),
                    ] {
                        if value == 0 {
                            findings.push(SchedulingDiagnostic::new(
                                format!("{block_path}/{member}"),
                                PolicyCheckReason::InvalidBound,
                            ));
                        }
                    }
                    check_identifier(&exact.pool, &format!("{block_path}/pool"), findings);
                    let horizon_minutes = u64::from(exact.horizon_days) * 24 * 60;
                    if u64::from(exact.lead_time_minutes) > horizon_minutes {
                        findings.push(SchedulingDiagnostic::new(
                            format!("{block_path}/leadTimeMinutes"),
                            PolicyCheckReason::LeadTimeBeyondHorizon,
                        ));
                    }
                }
            }
            SchedulingMode::ArrivalWindow => {
                if offering.exact_time.is_some() {
                    findings.push(SchedulingDiagnostic::new(
                        format!("{path}/exactTime"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
                if let Some(arrival) = &offering.arrival {
                    let block_path = format!("{path}/arrival");
                    check_identifier(&arrival.window, &format!("{block_path}/window"), findings);
                    for (member, value) in [
                        ("leadTimeMinutes", arrival.lead_time_minutes),
                        ("horizonDays", arrival.horizon_days),
                    ] {
                        if value == 0 {
                            findings.push(SchedulingDiagnostic::new(
                                format!("{block_path}/{member}"),
                                PolicyCheckReason::InvalidBound,
                            ));
                        }
                    }
                    let horizon_minutes = u64::from(arrival.horizon_days) * 24 * 60;
                    if u64::from(arrival.lead_time_minutes) > horizon_minutes {
                        findings.push(SchedulingDiagnostic::new(
                            format!("{block_path}/leadTimeMinutes"),
                            PolicyCheckReason::LeadTimeBeyondHorizon,
                        ));
                    }
                }
            }
        }

        if let Some(key) = &offering.duplicate_active_key {
            check_identifier(key, &format!("{path}/duplicateActiveKey"), findings);
        }
        check_collection_bound(&offering.reminders, &format!("{path}/reminders"), findings);
        let mut reminder_offsets: Vec<u32> = Vec::new();
        for (offset_index, reminder) in offering.reminders.iter().enumerate() {
            let reminder_path = format!("{path}/reminders/{offset_index}");
            if reminder.offset_minutes == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{reminder_path}/offsetMinutes"),
                    PolicyCheckReason::InvalidBound,
                ));
            }
            // Two offsets at the same distance would mint two intents due at
            // the same instant for one appointment: one reminder per moment.
            if reminder_offsets.contains(&reminder.offset_minutes) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{reminder_path}/offsetMinutes"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            } else {
                reminder_offsets.push(reminder.offset_minutes);
            }
            check_because(
                &reminder.because,
                &format!("{reminder_path}/because"),
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
            &format!("{path}/requiresCapabilities"),
            findings,
        );
        check_collection_bound(
            &offering.prerequisites,
            &format!("{path}/prerequisites"),
            findings,
        );
        for (capability_index, capability) in offering.requires_capabilities.iter().enumerate() {
            check_identifier(
                capability,
                &format!("{path}/requiresCapabilities/{capability_index}"),
                findings,
            );
        }
        for (prerequisite_index, prerequisite) in offering.prerequisites.iter().enumerate() {
            if !valid_reference(prerequisite) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{path}/prerequisites/{prerequisite_index}"),
                    PolicyCheckReason::InvalidIdentifier,
                ));
            }
        }
    }

    /// Validate the published windows in one environment-records document
    /// against this policy. Policy authoring can validate the identifier
    /// reference alone; existence and the window's capacity contract belong
    /// to the operator records that carry the supply.
    ///
    /// A finding about an offering's reference points into the project; a
    /// finding about a window points into the records, at `/windows`.
    pub fn check_window_records(&self, windows: &[PublishedWindow]) -> Vec<SchedulingDiagnostic> {
        let mut findings = Vec::new();
        if windows.len() > MAXIMUM_COLLECTION_ENTRIES {
            findings.push(SchedulingDiagnostic::records(
                "/windows",
                PolicyCheckReason::TooManyEntries,
            ));
        }
        for (index, offering) in self.offerings.iter().enumerate() {
            if let Some(arrival) = &offering.arrival {
                match windows.iter().find(|window| window.id == arrival.window) {
                    None => findings.push(SchedulingDiagnostic::new(
                        format!("/offerings/{index}/arrival/window"),
                        PolicyCheckReason::UnknownWindow,
                    )),
                    Some(window)
                        if window.offering != offering.id
                            || window.location != offering.location =>
                    {
                        findings.push(SchedulingDiagnostic::new(
                            format!("/offerings/{index}/arrival/window"),
                            PolicyCheckReason::MismatchedReference,
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        for (index, window) in windows.iter().enumerate() {
            let mut window_findings = Vec::new();
            self.check_window(window, windows, index, &mut window_findings);
            findings.extend(
                window_findings
                    .into_iter()
                    .map(|finding| finding.with_area(FindingArea::Records)),
            );
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
        let path = format!("/windows/{index}");
        check_identifier(&window.id, &format!("{path}/id"), findings);
        if window.revision == 0 {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/revision"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        check_because(&window.because, &format!("{path}/because"), findings);
        if windows
            .iter()
            .take(index)
            .any(|other| other.id == window.id)
        {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/id"),
                PolicyCheckReason::DuplicateIdentifier,
            ));
        }
        if window.units == 0 || window.units > MAXIMUM_UNITS {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/units"),
                PolicyCheckReason::InvalidBound,
            ));
        }
        if window.end <= window.start {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/end"),
                PolicyCheckReason::InvertedRange,
            ));
        }
        findings.extend(window.units_policy.check(&format!("{path}/unitsPolicy")));

        // A pool and a window anchor their capacity transactions on one row
        // keyed by the identifier, so the two supply namespaces must stay
        // disjoint. Sharing an identifier makes the two publish paths write
        // the same row: one aborts on the key, the other leaves the wrong
        // kind standing and the next records swap deletes the anchor the
        // pool still depends on.
        if self.sells_pool(&window.id) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/id"),
                PolicyCheckReason::SupplyIdentifierCollision,
            ));
        }

        if window.leftover.is_some() {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/leftover"),
                PolicyCheckReason::LeftoverUnsupported,
            ));
        }

        match self.offering(&window.offering) {
            None => findings.push(SchedulingDiagnostic::new(
                format!("{path}/offering"),
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
                        format!("{path}/offering"),
                        PolicyCheckReason::WrongModeField,
                    ));
                }
            }
        }

        let mut channels = Vec::new();
        let mut subquota_units = 0_u32;
        for (subquota_index, subquota) in window.subquotas.iter().enumerate() {
            let subquota_path = format!("{path}/subquotas/{subquota_index}");
            check_identifier(&subquota.id, &format!("{subquota_path}/id"), findings);
            check_because(
                &subquota.because,
                &format!("{subquota_path}/because"),
                findings,
            );
            if subquota.units == 0 {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}/units"),
                    PolicyCheckReason::InvalidBound,
                ));
            } else {
                subquota_units = subquota_units.saturating_add(subquota.units);
            }
            if channels.contains(&subquota.channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}/channel"),
                    PolicyCheckReason::DuplicateIdentifier,
                ));
            }
            // The declared set is closed: a subquota may not limit capacity
            // for a channel the deployment does not say it serves.
            if !self.channels.contains(&subquota.channel) {
                findings.push(SchedulingDiagnostic::new(
                    format!("{subquota_path}/channel"),
                    PolicyCheckReason::UnknownChannel,
                ));
            }
            channels.push(subquota.channel);
        }
        if subquota_units > window.units {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/subquotas"),
                PolicyCheckReason::SubquotaOverdrawn,
            ));
        }

        if let Some(staffing) = &window.staffing {
            check_identifier(&staffing.pool, &format!("{path}/staffing/pool"), findings);
            check_because(
                &staffing.because,
                &format!("{path}/staffing/because"),
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
                    format!("{path}/staffing/pool"),
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
                    format!("{path}/staffing/pool"),
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
        collection: Collection,
        findings: &mut Vec<SchedulingDiagnostic>,
    ) {
        let index = path
            .rsplit('/')
            .next()
            .and_then(|segment| segment.parse::<usize>().ok())
            .unwrap_or(0);
        let repeated = match collection {
            Collection::Offerings => self
                .offerings
                .iter()
                .take(index)
                .any(|offering| offering.id == id),
            Collection::Openings => self
                .openings
                .iter()
                .take(index)
                .any(|opening| opening.id == id),
            Collection::HolidaySets => self.holiday_sets.iter().take(index).any(|set| set.id == id),
        };
        if repeated {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/id"),
                PolicyCheckReason::DuplicateIdentifier,
            ));
        }
    }
}

/// A project collection whose entries carry unique ids.
#[derive(Clone, Copy)]
enum Collection {
    Offerings,
    Openings,
    HolidaySets,
}

fn check_scheduling_hook(hook: &HookPolicy, path: &str, findings: &mut Vec<SchedulingDiagnostic>) {
    let ObserverHandler::Url { destination_id } = &hook.handler;
    if !valid_hook_destination_id(destination_id) {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}/handler/destinationId"),
            PolicyCheckReason::InvalidHookDestination,
        ));
    }
    let allowed_projection = hook.trigger.projection_fields();
    for (field_index, field) in hook.projection.iter().enumerate() {
        if !allowed_projection.contains(&field.as_str()) {
            findings.push(SchedulingDiagnostic::new(
                format!("{path}/projection/{field_index}"),
                PolicyCheckReason::UnsupportedHookProjection,
            ));
        }
    }
}

fn valid_hook_destination_id(value: &str) -> bool {
    valid_identifier(value)
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

fn push_unique(
    seen: &mut Vec<String>,
    id: &str,
    path: &str,
    findings: &mut Vec<SchedulingDiagnostic>,
) {
    if seen.iter().any(|known| known == id) {
        findings.push(SchedulingDiagnostic::new(
            format!("{path}/id"),
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
            PolicyCheckReason::TooManyEntries,
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

fn check_label(label: &str, path: &str, findings: &mut Vec<SchedulingDiagnostic>) {
    if label.trim().is_empty() || label.len() > MAXIMUM_LABEL_BYTES {
        findings.push(SchedulingDiagnostic::new(
            path,
            PolicyCheckReason::InvalidLabel,
        ));
    }
}

/// The identifier grammar shared by every Scheduling id, the local
/// identifier of CFG-ID-1: non-empty, at most 64 bytes, starting with a
/// lowercase letter and continuing with lowercase letters, digits, hyphens,
/// and underscores.
#[must_use]
pub fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

/// A reference an offering may require a party to hold: a stable scoped
/// identifier such as `case:1234` or `urn:...`.
#[must_use]
pub fn valid_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub(crate) fn valid_hh_mm(value: &str) -> bool {
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

pub(crate) fn valid_iso_date(value: &str) -> bool {
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
    use crate::naming::AUTHORED_POLICY_FILE;
    use chrono::TimeZone as _;

    fn utc(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 10, hour, minute, 0).unwrap()
    }

    const MINIMAL_EXACT_TIME_PROJECT: &str = r#"
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
      pool: update-stations
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

    fn decode(yaml: &str) -> SchedulingPolicy {
        SchedulingPolicy::decode(AUTHORED_POLICY_FILE, yaml.as_bytes())
            .unwrap_or_else(|report| panic!("{}", report.render_human()))
            .value
    }

    /// The diagnostics a refused project reports, as `pointer code`.
    fn refusals(yaml: &str) -> Vec<String> {
        match SchedulingPolicy::read(AUTHORED_POLICY_FILE, yaml.as_bytes()) {
            Ok(_) => Vec::new(),
            Err(report) => report
                .diagnostics()
                .iter()
                .map(|diagnostic| format!("{} {}", diagnostic.path, diagnostic.code))
                .collect(),
        }
    }

    fn rendered(findings: &[SchedulingDiagnostic]) -> Vec<String> {
        findings.iter().map(ToString::to_string).collect()
    }

    pub fn minimal_exact_time_policy() -> SchedulingPolicy {
        decode(MINIMAL_EXACT_TIME_PROJECT)
    }

    pub fn household_window_policy() -> SchedulingPolicy {
        decode(
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
        )
    }

    fn household_windows() -> Vec<PublishedWindow> {
        crate::typed::decode_fragment::<Vec<PublishedWindow>>(
            r#"
- id: household-morning-window
  revision: 2
  offering: household-morning
  location: civic-hall
  start: 2026-10-10T08:00:00Z
  end: 2026-10-10T10:00:00Z
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
  because: The Saturday morning household block, sized for two officers.
"#,
        )
        .expect("the household window records read")
    }

    fn exact_time_offering(pool: &str) -> OfferingPolicy {
        OfferingPolicy {
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
                pool: pool.to_owned(),
                start_increment_minutes: 5,
                maximum_recipients: 1,
            }),
            arrival: None,
            cancellation_cutoff_minutes: 60,
            reminders: Vec::new(),
            duplicate_active_key: None,
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        }
    }

    #[test]
    fn the_minimal_policies_carry_no_findings() {
        assert_eq!(
            rendered(&minimal_exact_time_policy().check()),
            Vec::<String>::new()
        );
        assert_eq!(
            rendered(&household_window_policy().check()),
            Vec::<String>::new()
        );
        assert_eq!(refusals(MINIMAL_EXACT_TIME_PROJECT), Vec::<String>::new());
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

    /// The stored form of a project is the authored form: it reads back
    /// through the same types, writes no null, and spells every renamed
    /// member the way the project file does.
    #[test]
    fn the_stored_form_reads_back_as_written() {
        let policy = minimal_exact_time_policy();
        let stored = serde_json::to_value(&policy).expect("the project serializes");
        assert_eq!(
            stored["project"],
            serde_json::json!({"id": "registry-updates", "version": "1"})
        );
        assert_eq!(stored["offerings"][0]["exactTime"]["maximumRecipients"], 1);
        assert_eq!(stored["holdPolicy"]["maximumPerCaller"], 3);
        assert!(stored["offerings"][0].get("arrival").is_none());
        assert!(stored["offerings"][0].get("requiresCapabilities").is_none());
        assert!(stored.get("hooks").is_none());
        let read_back: SchedulingPolicy =
            serde_json::from_value(stored).expect("the stored form reads back");
        assert_eq!(read_back, policy);
    }

    #[test]
    fn envelope_and_identity_findings_are_path_addressed() {
        let mut policy = minimal_exact_time_policy();
        policy.api_version = "registry.registrystack.org/other/v1".to_owned();
        policy.kind = "Other".to_owned();
        policy.project.version = " ".to_owned();
        let rendered = rendered(&policy.check());
        assert!(rendered
            .contains(&"/apiVersion: scheduling.project.unsupported-api-version".to_owned()));
        assert!(rendered.contains(&"/kind: scheduling.project.unsupported-kind".to_owned()));
        assert!(rendered.contains(&"/project/version: scheduling.project.empty-text".to_owned()));
    }

    /// The retired apiVersion and every renamed member are refused by the
    /// reader, each at its position, with the replacement to write.
    #[test]
    fn the_retired_spelling_is_refused_naming_its_replacement() {
        let retired = MINIMAL_EXACT_TIME_PROJECT.replace(
            "id.registrystack.org/formats/scheduling/project/v1alpha1",
            "registry.registrystack.org/scheduling-policy-package/v1alpha1",
        );
        let report = SchedulingPolicy::read(AUTHORED_POLICY_FILE, retired.as_bytes())
            .expect_err("the retired apiVersion is refused");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.path, "/apiVersion");
        assert!(diagnostic
            .suggested_action
            .contains("id.registrystack.org/formats/scheduling/project/v1alpha1"));

        let renamed = MINIMAL_EXACT_TIME_PROJECT
            .replace(
                "project:\n  id: registry-updates\n  version: \"1\"",
                "scheduling:\n  id: registry-updates\n  version: 1",
            )
            .replace("maximumRecipients", "maxRecipients")
            .replace("maximumPerCaller", "maxPerCaller");
        let report = SchedulingPolicy::read(AUTHORED_POLICY_FILE, renamed.as_bytes())
            .expect_err("the renamed members are refused");
        let paths: Vec<&str> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect();
        for path in [
            "/scheduling",
            "/offerings/0/exactTime/maxRecipients",
            "/holdPolicy/maxPerCaller",
        ] {
            assert!(paths.contains(&path), "{paths:?}");
        }
        for diagnostic in report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.removed-key")
        {
            assert!(
                diagnostic.suggested_action.starts_with("Write "),
                "{}",
                diagnostic.suggested_action
            );
        }
    }

    /// CFG-EMPTY-2: a restricting list written empty would read as "no
    /// restriction", so the reader refuses it and names the omission; the
    /// served channel set is required and holds at least one channel.
    #[test]
    fn an_empty_restricting_list_is_refused_and_names_the_omission() {
        for (from, to, pointer) in [
            (
                "    cancellationCutoffMinutes: 240\n",
                "    cancellationCutoffMinutes: 240\n    requiresCapabilities: []\n",
                "/offerings/0/requiresCapabilities config.",
            ),
            (
                "    cancellationCutoffMinutes: 240\n",
                "    cancellationCutoffMinutes: 240\n    prerequisites: []\n",
                "/offerings/0/prerequisites config.",
            ),
            (
                "    dates: [\"2026-12-25\"]\n",
                "    dates: []\n",
                "/holidaySets/0/dates config.",
            ),
        ] {
            let yaml = MINIMAL_EXACT_TIME_PROJECT.replace(from, to);
            let refusals = refusals(&yaml);
            assert!(
                refusals.iter().any(|refusal| refusal.starts_with(pointer)),
                "{refusals:?}"
            );
        }

        let yaml =
            MINIMAL_EXACT_TIME_PROJECT.replace("channels: [public, assisted]", "channels: []");
        assert_eq!(
            refusals(&yaml),
            ["/channels scheduling.project.empty-collection"]
        );
        let yaml = MINIMAL_EXACT_TIME_PROJECT.replace("channels: [public, assisted]\n", "");
        assert_eq!(refusals(&yaml).len(), 1, "{:?}", refusals(&yaml));
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
        let rendered = rendered(&policy.check());
        assert!(rendered
            .contains(&"/offerings/0/exactTime: scheduling.project.missing-mode-field".to_owned()));
        // The stray arrival block is refused as a whole; its window reference
        // is not validated because the block must be removed, not repaired.
        assert!(rendered
            .contains(&"/offerings/0/arrival: scheduling.project.wrong-mode-field".to_owned()));
    }

    /// A finding about a member the file never writes is placed at the key
    /// of the nearest member it does write.
    #[test]
    fn a_finding_on_an_absent_member_is_placed_at_its_nearest_written_ancestor() {
        let yaml = MINIMAL_EXACT_TIME_PROJECT
            .replace("    mode: exact-time\n", "    mode: arrival-window\n");
        let report = SchedulingPolicy::read(AUTHORED_POLICY_FILE, yaml.as_bytes())
            .expect_err("a mode without its block is refused");
        let missing = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "scheduling.project.missing-mode-field")
            .expect("the missing block is reported");
        assert_eq!(missing.path, "/offerings/0/arrival");
        assert!(missing.source.is_some());
    }

    #[test]
    fn references_into_missing_collections_are_named() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].service = "no-such-service".to_owned();
        policy.openings[0].holiday_set = "no-such-holidays".to_owned();
        let rendered = rendered(&policy.check());
        assert!(rendered
            .contains(&"/offerings/0/service: scheduling.project.unknown-service".to_owned()));
        assert!(rendered.contains(
            &"/openings/0/holidaySet: scheduling.project.unknown-holiday-set".to_owned()
        ));
    }

    #[test]
    fn every_arrival_offering_must_own_its_referenced_window() {
        let mut policy = household_window_policy();
        let windows = household_windows();
        let mut neighbour = policy.offerings[0].clone();
        neighbour.id = "household-afternoon".to_owned();
        policy.offerings.push(neighbour);

        let rendered = rendered(&policy.check_window_records(&windows));
        assert!(rendered.contains(
            &"/offerings/1/arrival/window: scheduling.project.mismatched-reference".to_owned()
        ));
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
        assert_eq!(rendered(&policy.check()), Vec::<String>::new());

        policy.openings[0].effective_until =
            until(u64::from(registry_platform_calendar::MAXIMUM_PATTERN_SPAN_DAYS) + 1);
        let rendered = rendered(&policy.check());
        assert!(rendered.contains(
            &"/openings/0/effectiveUntil: scheduling.project.pattern-span-too-large".to_owned()
        ));
    }

    #[test]
    fn duplicate_ids_across_one_collection_are_rejected() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings.push(policy.offerings[0].clone());
        let rendered = rendered(&policy.check());
        assert_eq!(
            rendered
                .iter()
                .filter(|f| f.ends_with("duplicate-identifier"))
                .count(),
            1,
            "{rendered:?}"
        );
        assert!(rendered
            .contains(&"/offerings/1/id: scheduling.project.duplicate-identifier".to_owned()));
    }

    /// Authored reminder offsets are part of the reviewed policy: a zero
    /// offset, a blank because, and two offsets at the same distance are all
    /// findings, and a well-formed schedule passes the check untouched.
    #[test]
    fn reminder_offsets_are_validated_like_every_authored_choice() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0].reminders = vec![
            ReminderOffsetPolicy {
                offset_minutes: 0,
                because: "   ".to_owned(),
            },
            ReminderOffsetPolicy {
                offset_minutes: 1440,
                because: "One reminder the day before a counter update.".to_owned(),
            },
            ReminderOffsetPolicy {
                offset_minutes: 1440,
                because: "A second reminder at the same distance.".to_owned(),
            },
        ];
        let rendered_findings = rendered(&policy.check());
        assert!(rendered_findings.contains(
            &"/offerings/0/reminders/0/offsetMinutes: scheduling.project.invalid-bound".to_owned()
        ));
        assert!(rendered_findings.contains(
            &"/offerings/0/reminders/0/because: scheduling.project.invalid-because".to_owned()
        ));
        assert!(rendered_findings.contains(
            &"/offerings/0/reminders/2/offsetMinutes: scheduling.project.duplicate-identifier"
                .to_owned()
        ));

        policy.offerings[0].reminders.truncate(2);
        policy.offerings[0].reminders[0] = ReminderOffsetPolicy {
            offset_minutes: 60,
            because: "One reminder an hour before.".to_owned(),
        };
        assert_eq!(rendered(&policy.check()), Vec::<String>::new());
    }

    #[test]
    fn subquota_slices_may_not_overdraw_the_window() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].subquotas[0].units = 3;
        let rendered = rendered(&policy.check_window_records(&windows));
        assert!(rendered
            .contains(&"/windows/0/subquotas: scheduling.records.subquota-overdrawn".to_owned()));
    }

    #[test]
    fn window_units_must_fit_the_ledger_column() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].units = i32::MAX as u32;
        assert_eq!(
            rendered(&policy.check_window_records(&windows)),
            Vec::<String>::new(),
            "the largest ledger allocation must remain valid"
        );

        windows[0].units = i32::MAX as u32 + 1;
        assert_eq!(
            rendered(&policy.check_window_records(&windows)),
            vec!["/windows/0/units: scheduling.records.invalid-bound".to_owned()]
        );
    }

    #[test]
    fn one_channel_may_not_hold_two_slices_of_one_window() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        windows[0].subquotas[1].channel = Channel::Public;
        let rendered = rendered(&policy.check_window_records(&windows));
        assert!(rendered.contains(
            &"/windows/0/subquotas/1/channel: scheduling.records.duplicate-identifier".to_owned()
        ));
    }

    /// COR-3 / D5(a): the declared channel set is closed and required. A
    /// subquota may not reserve capacity for a channel the deployment does
    /// not say it serves, a declaration naming one channel twice declares it
    /// once, and a project that declares no channel serves none: the empty
    /// set fails closed rather than open onto the whole vocabulary.
    #[test]
    fn a_subquota_may_not_draw_on_an_undeclared_channel() {
        let mut policy = household_window_policy();
        let windows = household_windows();
        // The window serves public and assisted; the deployment declares
        // only assisted.
        policy.channels = vec![Channel::Assisted];
        let rendered_findings = rendered(&policy.check_window_records(&windows));
        assert!(
            rendered_findings.contains(
                &"/windows/0/subquotas/0/channel: scheduling.records.unknown-channel".to_owned()
            ),
            "{rendered_findings:?}"
        );
        assert!(!rendered_findings
            .iter()
            .any(|finding| finding.starts_with("/windows/0/subquotas/1/channel:")));

        // An empty declaration is refused on the project, and every subquota
        // draws on an undeclared channel.
        policy.channels = Vec::new();
        assert!(rendered(&policy.check())
            .contains(&"/channels: scheduling.project.empty-collection".to_owned()));
        let rendered_findings = rendered(&policy.check_window_records(&windows));
        assert_eq!(
            rendered_findings
                .iter()
                .filter(|finding| finding.ends_with("unknown-channel"))
                .count(),
            2,
            "{rendered_findings:?}"
        );

        // A repeated declaration is a duplicate identifier.
        policy.channels = vec![Channel::Public, Channel::Public];
        let rendered_findings = rendered(&policy.check());
        assert!(
            rendered_findings
                .contains(&"/channels/1: scheduling.project.duplicate-identifier".to_owned()),
            "{rendered_findings:?}"
        );
        // The reader refuses the same repetition where it stands.
        let yaml = MINIMAL_EXACT_TIME_PROJECT
            .replace("channels: [public, assisted]", "channels: [public, public]");
        assert!(refusals(&yaml)
            .iter()
            .any(|refusal| refusal.starts_with("/channels/1 ")));
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
        assert_eq!(rendered(&policy.check()), Vec::<String>::new());
        assert_eq!(
            rendered(&policy.check_window_records(&windows)),
            Vec::<String>::new()
        );

        policy
            .offerings
            .push(exact_time_offering("household-morning-window"));

        // The policy alone already names both sides: the arrival offering
        // points at a window identifier its own exact-time offering sells.
        let rendered_findings = rendered(&policy.check());
        assert!(
            rendered_findings.contains(
                &"/offerings/0/arrival/window: scheduling.project.supply-identifier-collision"
                    .to_owned()
            ),
            "{rendered_findings:?}"
        );

        // The published record is refused in its own vocabulary, which is
        // the finding the two database writes carry.
        let rendered_findings = rendered(&policy.check_window_records(&windows));
        assert!(
            rendered_findings.contains(
                &"/windows/0/id: scheduling.records.supply-identifier-collision".to_owned()
            ),
            "{rendered_findings:?}"
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
        policy.offerings.push(exact_time_offering("officer-pool"));
        let shared = "/windows/0/staffing/pool: scheduling.records.shared-supply-unpartitioned";
        assert!(rendered(&policy.check_window_records(&windows)).contains(&shared.to_owned()));

        // A partition does not attribute the supply across modes, so the mix
        // is refused with the partition declared.
        windows[0].staffing = Some(WindowStaffing {
            pool: "officer-pool".to_owned(),
            reserved_members: Some(2),
            because: "Two of the four duty officers staff the block.".to_owned(),
        });
        assert!(rendered(&policy.check_window_records(&windows)).contains(&shared.to_owned()));

        // A partitioned staffing block over a pool no exact-time offering
        // sells makes the share explicit and passes.
        windows[0].staffing = Some(WindowStaffing {
            pool: "hall-officers".to_owned(),
            reserved_members: Some(2),
            because: "Two of the four duty officers staff the block.".to_owned(),
        });
        assert_eq!(
            rendered(&policy.check_window_records(&windows)),
            Vec::<String>::new()
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
        let shared_count = |windows: &[PublishedWindow]| {
            rendered(&policy.check_window_records(windows))
                .iter()
                .filter(|finding| finding.ends_with("shared-supply-unpartitioned"))
                .count()
        };
        // The second window's offering linkage is wrong on purpose in this
        // fixture; only the supply finding is asserted here.
        assert_eq!(shared_count(&windows), 2);

        // A whole-pool claim and an attributed subset still have independent
        // window ledgers, so the authored subset cannot make the overlap safe.
        windows[1].staffing.as_mut().unwrap().reserved_members = Some(1);
        assert_eq!(shared_count(&windows), 2);

        // Two attributed subsets are equally unenforceable: their claims lock
        // and consume separate window ids rather than a shared staffing slice.
        windows[0].staffing.as_mut().unwrap().reserved_members = Some(1);
        assert_eq!(shared_count(&windows), 2);

        // Disjoint windows may reuse the pool regardless of their advisory
        // attributed member counts.
        let disjoint = PublishedWindow {
            start: Utc.with_ymd_and_hms(2026, 10, 10, 13, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 10, 10, 15, 0, 0).unwrap(),
            ..windows[1].clone()
        };
        windows[1] = disjoint;
        assert_eq!(shared_count(&windows), 0);
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

    fn with_hooks(hooks: &str) -> String {
        format!("{MINIMAL_EXACT_TIME_PROJECT}hooks:\n{hooks}")
    }

    const OBSERVER: &str = "  - id: appointment-observer
    phase: after
    trigger: appointment.confirmed
    projection: []
    handler:
      type: url
      destinationId: appointment-events
";

    /// SEC-17 / SEC-24: an observer hook runs after commit, follows one of
    /// three appointment lifecycle triggers, receives only that trigger's
    /// closed projection, and delivers to a URL destination the runtime
    /// configuration binds. The reader refuses every other phase, trigger,
    /// and handler, and any condition or principal, each at its position;
    /// the semantic check refuses a projection field outside the closed set
    /// and a repeated id.
    #[test]
    fn scheduling_observer_hooks_accept_only_the_closed_runtime_contract() {
        let yaml = with_hooks(OBSERVER);
        assert_eq!(refusals(&yaml), Vec::<String>::new());
        let policy = decode(&yaml);
        let declarations = policy.hook_declarations();
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].phase, HookPhase::After);
        assert_eq!(declarations[0].trigger, APPOINTMENT_CONFIRMED_TRIGGER);
        assert!(declarations[0].when.is_none());
        assert!(declarations[0].principal.is_none());
        assert!(matches!(
            &declarations[0].handler,
            HookHandlerSource::Url { destination_id } if destination_id == "appointment-events"
        ));

        for (from, to, pointer) in [
            ("phase: after", "phase: before", "/hooks/0/phase "),
            (
                "trigger: appointment.confirmed",
                "trigger: hold.expired",
                "/hooks/0/trigger ",
            ),
            (
                "      type: url\n      destinationId: appointment-events\n",
                "      type: wasm\n      module: observer.wasm\n      abi: vendor.hook/v9\n",
                "/hooks/0/handler/type ",
            ),
            (
                "      type: url\n      destinationId: appointment-events\n",
                "      type: rhai\n      script: observer.rhai\n",
                "/hooks/0/handler/type ",
            ),
            (
                "destinationId: appointment-events",
                "destinationId: https://receiver.example",
                "/hooks/0/handler/destinationId ",
            ),
            (
                "    projection: []\n",
                "    projection: []\n    when:\n      state: active\n",
                "/hooks/0/when config.unknown-key",
            ),
            (
                "    projection: []\n",
                "    projection: []\n    principal: scheduling-hook\n",
                "/hooks/0/principal config.unknown-key",
            ),
            (
                "projection: []",
                "projection: [actor]",
                "/hooks/0/projection/0 scheduling.project.unsupported-hook-projection",
            ),
        ] {
            let refusals = refusals(&with_hooks(&OBSERVER.replace(from, to)));
            assert!(
                refusals.iter().any(|refusal| refusal.starts_with(pointer)),
                "{pointer}: {refusals:?}"
            );
        }

        let cancellation = OBSERVER
            .replace("appointment.confirmed", "appointment.cancelled")
            .replace("projection: []", "projection: [revision, reason]");
        assert_eq!(
            refusals(&with_hooks(&cancellation)),
            ["/hooks/0/projection/1 scheduling.project.unsupported-hook-projection"]
        );

        assert_eq!(
            refusals(&with_hooks(&format!("{OBSERVER}{OBSERVER}"))),
            ["/hooks/1/id scheduling.project.duplicate-identifier"]
        );

        // A project built in code is held to the same destination grammar.
        let mut policy = decode(&yaml);
        policy.hooks[0].handler = ObserverHandler::Url {
            destination_id: "https://receiver.example".to_owned(),
        };
        assert_eq!(
            rendered(&policy.check()),
            ["/hooks/0/handler/destinationId: scheduling.project.invalid-hook-destination"]
        );
    }

    /// The member spellings Scheduling hooks once carried, a repeated key,
    /// and a handler naming members of another handler type are refused by
    /// the reader, never silently narrowed.
    #[test]
    fn legacy_duplicate_and_mismatched_hook_members_are_refused_by_the_shared_shape() {
        for hooks in [
            "  - id: observer\n    abi: registry.scheduling-hook/v1\n    because: legacy\n",
            "  - id: observer\n    phase: after\n    phase: before\n    trigger: appointment.confirmed\n    projection: []\n    handler:\n      type: url\n      destinationId: appointment-events\n",
            "  - id: observer\n    phase: after\n    trigger: appointment.confirmed\n    projection: []\n    handler:\n      type: url\n      script: observer.rhai\n      abi: registry.hook-handler/v1\n",
            "  - id: observer\n    phase: after\n    trigger: appointment.confirmed\n    projection: []\n    handler:\n      kind: url\n      destinationId: appointment-events\n",
        ] {
            let refusals = refusals(&with_hooks(hooks));
            assert!(
                refusals.iter().any(|refusal| refusal.starts_with("/hooks/0")),
                "accepted:\n{hooks}\n{refusals:?}"
            );
        }
    }

    #[test]
    fn a_declared_leftover_policy_is_refused_because_nothing_reads_it() {
        let policy = household_window_policy();
        let mut windows = household_windows();
        assert!(policy.check_window_records(&windows).is_empty());

        windows[0].leftover = Some(LeftoverCapacityPolicy::BecomesWalkIn);
        assert_eq!(
            rendered(&policy.check_window_records(&windows)),
            ["/windows/0/leftover: scheduling.records.leftover-unsupported"]
        );
    }

    #[test]
    fn identifiers_dates_and_times_follow_their_grammars() {
        assert!(valid_identifier("north-counter-2"));
        assert!(valid_identifier("north_counter"));
        assert!(!valid_identifier("North"));
        assert!(!valid_identifier("north counter"));
        assert!(!valid_identifier("_north"));
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
    /// incomplete authoring. A well-formed value that ends before it starts
    /// is an inverted range: the text parses, the range does not hold.
    #[test]
    fn a_clock_or_date_outside_its_grammar_is_malformed_rather_than_unbounded() {
        let mut policy = minimal_exact_time_policy();
        policy.openings[0].start_time = "9:00 AM".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/openings/0/startTime: scheduling.project.malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].end_time = "12.30".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/openings/0/endTime: scheduling.project.malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].effective_from = "01/10/2026".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/openings/0/effectiveFrom: scheduling.project.malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.holiday_sets[0].dates[0] = "25 December 2026".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/holidaySets/0/dates/0: scheduling.project.malformed-value"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].end_time = "08:00".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/openings/0/endTime: scheduling.project.inverted-range"]
        );

        let mut policy = minimal_exact_time_policy();
        policy.openings[0].effective_until = "2026-09-30".to_owned();
        assert_eq!(
            rendered(&policy.check()),
            ["/openings/0/effectiveUntil: scheduling.project.inverted-range"]
        );
    }

    #[test]
    fn a_lead_time_past_the_horizon_is_refused_at_the_lead_time() {
        let mut policy = minimal_exact_time_policy();
        policy.offerings[0]
            .exact_time
            .as_mut()
            .unwrap()
            .horizon_days = 1;
        policy.offerings[0]
            .exact_time
            .as_mut()
            .unwrap()
            .lead_time_minutes = 1441;
        assert_eq!(
            rendered(&policy.check()),
            ["/offerings/0/exactTime/leadTimeMinutes: scheduling.project.lead-time-beyond-horizon"]
        );
    }

    #[test]
    fn weekdays_and_channels_serialize_in_their_published_spelling() {
        assert_eq!(
            serde_json::to_value(PolicyWeekday::Wed).unwrap(),
            serde_json::json!("wed")
        );
        assert_eq!(
            crate::typed::decode_fragment::<PolicyWeekday>("wed").unwrap(),
            PolicyWeekday::Wed
        );
        assert_eq!(Channel::WalkIn.as_str(), "walk-in");
        assert_eq!(
            crate::typed::decode_fragment::<Channel>("walk-in").unwrap(),
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
        let yaml = format!("{MINIMAL_EXACT_TIME_PROJECT}surprise: true\nanother: 1\n");
        let refusals = refusals(&yaml);
        assert!(
            refusals.contains(&"/surprise config.unknown-key".to_owned()),
            "{refusals:?}"
        );
        assert!(
            refusals.contains(&"/another config.unknown-key".to_owned()),
            "{refusals:?}"
        );
    }

    /// Every integer member reads within its real bound, refused where it
    /// stands without repeating the value.
    #[test]
    fn integer_members_are_bounded_by_the_reader() {
        for (from, to, pointer) in [
            (
                "ttlMinutes: 5",
                "ttlMinutes: 1441",
                "/holdPolicy/ttlMinutes",
            ),
            (
                "maximumPerCaller: 3",
                "maximumPerCaller: 0",
                "/holdPolicy/maximumPerCaller",
            ),
            (
                "durationMinutes: 30",
                "durationMinutes: 0",
                "/offerings/0/exactTime/durationMinutes",
            ),
            (
                "horizonDays: 60",
                "horizonDays: 3651",
                "/offerings/0/exactTime/horizonDays",
            ),
            ("revision: 1", "revision: 0", "/holidaySets/0/revision"),
        ] {
            let refusals = refusals(&MINIMAL_EXACT_TIME_PROJECT.replace(from, to));
            assert_eq!(refusals, [format!("{pointer} config.out-of-range")]);
        }
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
        let rendered_findings = rendered(&policy.check());
        assert!(rendered_findings
            .contains(&"/services: scheduling.project.too-many-entries".to_owned()));

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
        let rendered_findings = rendered(&policy.check());
        assert!(rendered_findings.contains(
            &"/offerings/0/requiresCapabilities: scheduling.project.too-many-entries".to_owned()
        ));
        assert!(rendered_findings.contains(
            &"/offerings/0/prerequisites: scheduling.project.too-many-entries".to_owned()
        ));

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
