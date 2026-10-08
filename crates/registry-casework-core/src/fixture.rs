// SPDX-License-Identifier: Apache-2.0
//! The offline test files a Casework project carries beside `casework.yaml`:
//! fixtures under `fixtures/`, simulations under `simulations/`, and the
//! holiday sets a simulation pins under `simulations/holiday-sets/`. Each is
//! read through the shared reader, and the checks here need no other file;
//! the checks against the project and its source descriptions belong to the
//! command that reads them all.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use registry_platform_yaml::{
    ApiVersion, BoundedU64, Decoded, Document, EnvelopeRule, Expect, ExternalId, FormatSpec,
    Invalid, LocalId, Reader, Refusal, RemovedKey, Report, RetiredApiVersion, ScalarHook,
    ScalarSite, Severity, UniqueList,
};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::config::contains_environment_expression;
use crate::finding::{findings_report, ConfigFinding};
use crate::{HolidaySetDocument, ReviewTiming, RoutingActivity, RoutingContext};

pub const CASEWORK_FIXTURE_API_VERSION: &str =
    "id.registrystack.org/formats/casework/fixture/v1alpha1";
pub const CASEWORK_FIXTURE_KIND: &str = "CaseworkFixture";
pub const CASEWORK_SIMULATION_API_VERSION: &str =
    "id.registrystack.org/formats/casework/simulation/v1alpha1";
pub const CASEWORK_SIMULATION_KIND: &str = "CaseworkSimulation";
pub const CASEWORK_HOLIDAY_SET_API_VERSION: &str =
    "id.registrystack.org/formats/casework/holiday-set/v1alpha1";
pub const CASEWORK_HOLIDAY_SET_KIND: &str = "CaseworkHolidaySet";

/// The largest holiday-set revision: the runtime stores it as a signed
/// 64-bit integer.
pub const MAXIMUM_HOLIDAY_SET_REVISION: u64 = i64::MAX as u64;
/// The most dates one holiday-set revision holds, the bound the runtime
/// accepts.
pub const MAXIMUM_HOLIDAY_SET_DATES: usize = 3_660;
/// The largest elapsed target, in minutes, that a whole number of seconds
/// held as a signed 64-bit integer can express.
pub const MAXIMUM_TARGET_ELAPSED_MINUTES: u64 = (i64::MAX / 60) as u64;
const MAXIMUM_MILLISECONDS: u64 = i64::MAX as u64;

/// The format of a file under `fixtures/` (CFG-ENV-1).
pub const CASEWORK_FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_FIXTURE_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/casework-fixture/v1alpha1",
            replacement: "Write apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1, rename name to id, write source as request: {source, entity} without reviewStage, and write targetElapsed as target: {elapsedMinutes: N}, or target: none for a request with no target.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/name",
            replacement: "Write the fixture identifier as id.",
        },
        RemovedKey {
            pointer: "/source",
            replacement: "Write request: {source: SOURCE_ID, entity: REQUEST_ENTITY}.",
        },
        RemovedKey {
            pointer: "/expect/targetElapsed",
            replacement: "Write target: {elapsedMinutes: N}, or target: none for a request with no target.",
        },
    ],
};

/// The format of a file under `simulations/` (CFG-ENV-1).
pub const CASEWORK_SIMULATION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_SIMULATION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_SIMULATION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/subject/id",
            replacement: "Write the source record identifier as subject.recordId.",
        },
        RemovedKey {
            pointer: "/expect/ruleId",
            replacement:
                "Write the routing rule as expect.rule, or rule: none when no rule matches.",
        },
    ],
};

/// The format of a file under `simulations/holiday-sets/` (CFG-ENV-1).
pub const CASEWORK_HOLIDAY_SET_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_HOLIDAY_SET_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_HOLIDAY_SET_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The three formats, in the order [`OfflineFileKind`] lists them.
pub const CASEWORK_OFFLINE_FORMATS: [FormatSpec<'static>; 3] = [
    CASEWORK_FIXTURE_FORMAT,
    CASEWORK_SIMULATION_FORMAT,
    CASEWORK_HOLIDAY_SET_FORMAT,
];

/// Which offline file a project directory holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineFileKind {
    Fixture,
    Simulation,
    HolidaySet,
}

impl OfflineFileKind {
    pub fn kind(self) -> &'static str {
        match self {
            OfflineFileKind::Fixture => CASEWORK_FIXTURE_KIND,
            OfflineFileKind::Simulation => CASEWORK_SIMULATION_KIND,
            OfflineFileKind::HolidaySet => CASEWORK_HOLIDAY_SET_KIND,
        }
    }

    /// The project directory that holds this kind of file.
    pub fn directory(self) -> &'static str {
        match self {
            OfflineFileKind::Fixture => "fixtures/",
            OfflineFileKind::Simulation => "simulations/",
            OfflineFileKind::HolidaySet => "simulations/holiday-sets/",
        }
    }

    fn from_kind(kind: &str) -> Option<Self> {
        [
            OfflineFileKind::Fixture,
            OfflineFileKind::Simulation,
            OfflineFileKind::HolidaySet,
        ]
        .into_iter()
        .find(|candidate| candidate.kind() == kind)
    }
}

/// One offline file, read and checked on its own.
pub enum OfflineFile {
    Fixture(Box<Decoded<CaseworkFixture>>),
    Simulation(Box<Decoded<CaseworkSimulation>>),
    HolidaySet(Box<Decoded<CaseworkHolidaySet>>),
}

/// Read one file found in the directory that holds `expected` files. The
/// envelope identifies the file (CFG-CHECK-2): a fixture, simulation, or
/// holiday set in another kind's directory is refused at `/kind`, and any
/// other kind is refused as the wrong kind.
pub fn read_offline_file(
    file: &str,
    bytes: &[u8],
    expected: OfflineFileKind,
) -> Result<OfflineFile, Report> {
    let mut hook = AuthoredOnly;
    let document = Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::new(&CASEWORK_OFFLINE_FORMATS))?;
    let found = OfflineFileKind::from_kind(&document.envelope().kind);
    if found != Some(expected) {
        let message = match found {
            Some(OfflineFileKind::Fixture) => "a CaseworkFixture belongs under fixtures/",
            Some(OfflineFileKind::Simulation) => "a CaseworkSimulation belongs under simulations/",
            _ => "a CaseworkHolidaySet belongs under simulations/holiday-sets/",
        };
        let action = match found {
            Some(OfflineFileKind::Fixture) => "Move the file to fixtures/.",
            Some(OfflineFileKind::Simulation) => "Move the file to simulations/.",
            _ => "Move the file to simulations/holiday-sets/.",
        };
        let mut report = document.warnings();
        report.push(document.diagnostic_at_value(
            Severity::Error,
            "casework.project.misplaced-file",
            "/kind",
            message,
            action,
        ));
        return Err(report);
    }
    match expected {
        OfflineFileKind::Fixture => checked(document, CaseworkFixture::findings)
            .map(|decoded| OfflineFile::Fixture(Box::new(decoded))),
        OfflineFileKind::Simulation => checked(document, |_| Vec::new())
            .map(|decoded| OfflineFile::Simulation(Box::new(decoded))),
        OfflineFileKind::HolidaySet => checked(document, CaseworkHolidaySet::findings)
            .map(|decoded| OfflineFile::HolidaySet(Box::new(decoded))),
    }
}

fn checked<T: serde::de::DeserializeOwned>(
    document: Document,
    findings: impl Fn(&T) -> Vec<ConfigFinding>,
) -> Result<Decoded<T>, Report> {
    let value = document.decode::<T>()?;
    let found = findings(&value);
    if found.is_empty() {
        Ok(Decoded { value, document })
    } else {
        Err(findings_report(&document, &found))
    }
}

fn read_one<T: serde::de::DeserializeOwned>(
    file: &str,
    bytes: &[u8],
    format: &FormatSpec<'_>,
    findings: impl Fn(&T) -> Vec<ConfigFinding>,
) -> Result<Decoded<T>, Report> {
    let mut hook = AuthoredOnly;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<T>(bytes, &Expect::one(format))?;
    let found = findings(&decoded.value);
    if found.is_empty() {
        Ok(decoded)
    } else {
        Err(findings_report(&decoded.document, &found))
    }
}

/// Refuses every `${...}` expression: an offline file is read as written,
/// and substitution applies to `runtime.yaml` only (CFG-SEC-2).
struct AuthoredOnly;

impl AuthoredOnly {
    fn check(site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if !contains_environment_expression(site.text) {
            return Ok(());
        }
        Err(Refusal {
            code: "config.substitution-not-allowed".to_owned(),
            message: "a `${...}` expression is written in an offline test file; substitution applies to runtime.yaml only".to_owned(),
            suggested_action: "Write the value directly; fixtures, simulations, and holiday sets are read as written.".to_owned(),
        })
    }
}

impl ScalarHook for AuthoredOnly {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site).map(|()| None)
    }
}

/// An RFC 3339 timestamp with an offset (CFG-VAL-5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn get(self) -> DateTime<Utc> {
        self.0
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&text)
            .map(|parsed| Timestamp(parsed.with_timezone(&Utc)))
            .map_err(|_| {
                Invalid::expected(
                    "an RFC 3339 timestamp with an offset",
                    "Write the timestamp with its offset, such as 2026-09-11T17:00:00+07:00.",
                )
                .into_error()
            })
    }
}

/// A calendar date, `YYYY-MM-DD` (CFG-VAL-5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CalendarDate(NaiveDate);

impl CalendarDate {
    pub fn get(self) -> NaiveDate {
        self.0
    }
}

impl fmt::Display for CalendarDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.format("%Y-%m-%d"))
    }
}

impl<'de> Deserialize<'de> for CalendarDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = text.as_bytes();
        let shaped = bytes.len() == 10
            && bytes.iter().enumerate().all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                _ => byte.is_ascii_digit(),
            });
        shaped
            .then(|| NaiveDate::parse_from_str(&text, "%Y-%m-%d").ok())
            .flatten()
            .map(CalendarDate)
            .ok_or_else(|| {
                Invalid::expected(
                    "a calendar date written YYYY-MM-DD",
                    "Write the date as YYYY-MM-DD, such as 2026-09-07.",
                )
                .into_error()
            })
    }
}

#[cfg(feature = "schema")]
mod schema_impls {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::{CalendarDate, SimulatedFieldValue, Timestamp};

    impl JsonSchema for Timestamp {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("Timestamp")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "format": "date-time",
                "description": "An RFC 3339 timestamp with an offset, such as 2026-09-11T17:00:00+07:00.",
            })
        }
    }

    impl JsonSchema for SimulatedFieldValue {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("SimulatedFieldValue")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["boolean", "number", "string"],
                "description": "A routing field value: a boolean, a number, or text. A field the record does not carry is omitted.",
            })
        }
    }

    impl JsonSchema for CalendarDate {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("CalendarDate")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "format": "date",
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                "description": "A calendar date written YYYY-MM-DD.",
            })
        }
    }
}

/// One revision of a holiday set, as a simulation pins it
/// (`simulations/holiday-sets/<holidaySet>-<revision>.yaml`).
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkHolidaySet {
    pub api_version: String,
    pub kind: String,
    /// The holiday set a calendar names in `holidaySet`.
    pub holiday_set: LocalId,
    pub revision: BoundedU64<1, MAXIMUM_HOLIDAY_SET_REVISION>,
    /// The dates that are not working days, at most 3660.
    #[cfg_attr(feature = "schema", schemars(length(max = 3660)))]
    pub dates: UniqueList<CalendarDate>,
}

impl CaseworkHolidaySet {
    /// Read and check one holiday-set file through the shared reader.
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        read_one(file, bytes, &CASEWORK_HOLIDAY_SET_FORMAT, Self::findings)
    }

    fn findings(&self) -> Vec<ConfigFinding> {
        if self.dates.len() <= MAXIMUM_HOLIDAY_SET_DATES {
            return Vec::new();
        }
        vec![ConfigFinding::new(
            "casework.holiday-set.too-many-dates",
            "/dates",
            "expected at most 3660 dates in one holiday-set revision",
            "Keep at most 3660 dates in one revision, the bound the runtime accepts.",
        )]
    }

    /// The revision as the runtime's holiday-set document.
    pub fn to_document(&self) -> HolidaySetDocument {
        HolidaySetDocument {
            holiday_set: self.holiday_set.to_string(),
            revision: self.revision.get(),
            dates: self.dates.iter().map(ToString::to_string).collect(),
        }
    }
}

/// One offline routing and clock simulation of a source request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkSimulation {
    pub api_version: String,
    pub kind: String,
    pub id: LocalId,
    /// The `sources[].id` in `casework.yaml` the subject comes from.
    pub source: ExternalId,
    /// The revision of each holiday set the simulation pins, by holiday-set
    /// id; the file is `holiday-sets/<id>-<revision>.yaml` beside this one.
    #[serde(default)]
    pub holiday_revisions: BTreeMap<LocalId, BoundedU64<1, MAXIMUM_HOLIDAY_SET_REVISION>>,
    pub subject: SimulationSubject,
    /// The instant the clock state is evaluated at.
    pub now: Timestamp,
    pub expect: SimulationExpectation,
}

impl CaseworkSimulation {
    /// Read one simulation file through the shared reader.
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        read_one(file, bytes, &CASEWORK_SIMULATION_FORMAT, |_| Vec::new())
    }
}

/// The source request a simulation routes.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationSubject {
    /// The request entity a `sources[].requests[].entity` names.
    pub entity: ExternalId,
    /// The source record identifier.
    pub record_id: ExternalId,
    /// The source record version.
    pub version: ExternalId,
    pub activity: SubjectActivity,
    /// The source stage the record is in.
    #[serde(default)]
    pub stage: Option<ExternalId>,
    /// Routing field values, by the field id the request's projection names.
    /// A field the record does not carry is omitted.
    #[serde(default)]
    pub fields: BTreeMap<ExternalId, SimulatedFieldValue>,
    /// When the record entered its stage; an activity clock starts here.
    #[serde(default)]
    pub stage_entered_at: Option<Timestamp>,
    /// The source's review timing; a subject clock reads it.
    #[serde(default)]
    pub review_timing: Option<SimulationReviewTiming>,
}

impl SimulationSubject {
    /// The routing input the runtime evaluates for this subject.
    pub fn routing_context(&self) -> RoutingContext {
        RoutingContext {
            activity: self.activity.routing(),
            stage: self.stage.as_ref().map(ToString::to_string),
            fields: self
                .fields
                .iter()
                .map(|(field, value)| (field.to_string(), value.to_value()))
                .collect(),
        }
    }
}

/// A routing field value a simulated subject carries: a boolean, a number,
/// or text. Routing reads a null field exactly as an absent one, so null
/// says nothing omission does not, and the reader refuses it (CFG-EMPTY-1):
/// a field the record does not carry is omitted.
#[derive(Clone, Debug, PartialEq)]
pub enum SimulatedFieldValue {
    Boolean(bool),
    Number(serde_json::Number),
    String(String),
}

const EXPECT_SIMULATED_FIELD_VALUE: &str = "a boolean, a number, or text";

impl SimulatedFieldValue {
    /// The value as routing compares it.
    pub fn to_value(&self) -> Value {
        match self {
            SimulatedFieldValue::Boolean(value) => Value::Bool(*value),
            SimulatedFieldValue::Number(value) => Value::Number(value.clone()),
            SimulatedFieldValue::String(value) => Value::String(value.clone()),
        }
    }
}

impl Serialize for SimulatedFieldValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SimulatedFieldValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Scalar;

        impl Visitor<'_> for Scalar {
            type Value = SimulatedFieldValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(EXPECT_SIMULATED_FIELD_VALUE)
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(SimulatedFieldValue::Boolean(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(SimulatedFieldValue::Number(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(SimulatedFieldValue::Number(value.into()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(SimulatedFieldValue::Number)
                    .ok_or_else(|| {
                        Invalid::expected(
                            EXPECT_SIMULATED_FIELD_VALUE,
                            "Write true, false, a finite number, or text.",
                        )
                        .into_error()
                    })
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SimulatedFieldValue::String(value.to_string()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(SimulatedFieldValue::String(value))
            }
        }

        deserializer.deserialize_any(Scalar)
    }
}

/// The activity a simulated record is in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SubjectActivity {
    Review,
    Apply,
}

impl SubjectActivity {
    pub fn routing(self) -> RoutingActivity {
        match self {
            SubjectActivity::Review => RoutingActivity::Review,
            SubjectActivity::Apply => RoutingActivity::Apply,
        }
    }
}

/// The source's request-wide review timing.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationReviewTiming {
    pub first_submitted_at: Timestamp,
    /// Completed pause intervals.
    pub paused_milliseconds: BoundedU64<0, MAXIMUM_MILLISECONDS>,
    /// The start of an open pause; absent when the review is not paused.
    #[serde(default)]
    pub pause_started_at: Option<Timestamp>,
    /// The final completion; absent while the review is open.
    #[serde(default)]
    pub completed_at: Option<Timestamp>,
}

impl SimulationReviewTiming {
    pub fn to_timing(&self) -> ReviewTiming {
        ReviewTiming {
            first_submitted_at: self.first_submitted_at.get(),
            paused_milliseconds: i64::try_from(self.paused_milliseconds.get()).unwrap_or(i64::MAX),
            pause_started_at: self.pause_started_at.map(Timestamp::get),
            completed_at: self.completed_at.map(Timestamp::get),
        }
    }
}

/// What a simulation expects. An absent member is not checked (CFG-EMPTY-6).
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationExpectation {
    /// The queue routing selects.
    pub queue: ExternalId,
    /// The routing rule that matched, or `none` when no rule matched and the
    /// request's default queue applies.
    #[serde(default)]
    pub rule: Option<LocalId>,
    /// The activity or subject clock's due instant.
    #[serde(default)]
    pub due_at: Option<Timestamp>,
    /// The activity clock's state at `now`.
    #[serde(default)]
    pub due_state: Option<DueState>,
    /// The activity clock reminders due at `now`.
    #[serde(default)]
    pub eligible_reminders: Option<UniqueList<LocalId>>,
    /// The activity clock steps due at `now`.
    #[serde(default)]
    pub eligible_steps: Option<UniqueList<LocalId>>,
    /// The subject clock's remaining budget at `now`.
    #[serde(default)]
    pub remaining_milliseconds: Option<BoundedU64<0, MAXIMUM_MILLISECONDS>>,
}

/// The value of `expect.rule` that states no routing rule matched.
pub const NO_RULE: &str = "none";

/// An activity clock's state at an instant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum DueState {
    Pending,
    AtRisk,
    Due,
}

/// One offline check of a review kind or a source request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkFixture {
    pub api_version: String,
    pub kind: String,
    pub id: LocalId,
    /// A review kind and the display a producer sends; write this or
    /// `request`.
    #[serde(default)]
    pub review: Option<FixtureReview>,
    /// A source request; write this or `review`.
    #[serde(default)]
    pub request: Option<FixtureRequest>,
    pub expect: FixtureExpectation,
}

impl CaseworkFixture {
    /// Read and check one fixture file through the shared reader.
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        read_one(file, bytes, &CASEWORK_FIXTURE_FORMAT, Self::findings)
    }

    fn findings(&self) -> Vec<ConfigFinding> {
        let mut findings = Vec::new();
        match (&self.review, &self.request) {
            (None, None) => findings.push(ConfigFinding::new(
                "casework.fixture.no-subject",
                "",
                "the fixture names neither review nor request",
                "Write review: {kind, display} to test a review kind, or request: {source, entity} to test a source request.",
            )),
            (Some(_), Some(_)) => findings.push(ConfigFinding::new(
                "casework.fixture.two-subjects",
                "/request",
                "the fixture names both review and request",
                "Keep one: a fixture tests one review kind or one source request; write a second fixture for the other.",
            )),
            (Some(_), None) => {
                for (member, present) in [
                    ("target", self.expect.target.is_some()),
                    ("applicationMode", self.expect.application_mode.is_some()),
                ] {
                    if present {
                        findings.push(ConfigFinding::new(
                            "casework.fixture.request-expectation",
                            format!("/expect/{member}"),
                            "this expectation describes a source request, and the fixture tests a review kind",
                            "Remove the member, or test a source request with request: {source, entity}.",
                        ));
                    }
                }
            }
            (None, Some(_)) => {
                if self.expect.outcomes.is_some() {
                    findings.push(ConfigFinding::new(
                        "casework.fixture.review-expectation",
                        "/expect/outcomes",
                        "outcomes describes a review kind, and the fixture tests a source request",
                        "Remove outcomes, or test a review kind with review: {kind, display}.",
                    ));
                }
            }
        }
        findings
    }
}

/// The review kind a fixture checks.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureReview {
    /// The `reviewKinds[].id` in `casework.yaml`.
    pub kind: LocalId,
    /// A display the kind's `displaySchema` must accept, keyed by the
    /// property names that schema declares.
    #[cfg_attr(feature = "schema", schemars(schema_with = "display_schema"))]
    pub display: Map<String, Value>,
}

/// A display is an instance of the review kind's own `displaySchema`, so this
/// schema states only what every display shares: keys are names that schema
/// declares, and no value is `null` (CFG-EMPTY-1). Each value is read by the
/// kind's `displaySchema`, which `caseworkctl check` applies (CFG-EMBED-2).
#[cfg(feature = "schema")]
fn display_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names = generator.subschema_for::<ExternalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": {
            "type": ["string", "number", "boolean", "object", "array"],
            "description": "A value the review kind's displaySchema declares for this name.",
            "x-registry-foreign": "casework-review-display",
        },
    })
}

/// The source request a fixture checks.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureRequest {
    /// The `sources[].id` in `casework.yaml`.
    pub source: ExternalId,
    /// The request entity a `sources[].requests[].entity` names.
    pub entity: ExternalId,
}

/// What a fixture expects. An absent member is not checked (CFG-EMPTY-6).
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureExpectation {
    /// The queue a review kind's first stage, or a source request, uses.
    pub queue: ExternalId,
    /// The outcome ids the review kind offers.
    #[serde(default)]
    pub outcomes: Option<UniqueList<LocalId>>,
    /// The request's elapsed target, or `none` for a request with no target.
    #[serde(default)]
    pub target: Option<TargetExpectation>,
    /// How the source applies an approved request.
    #[serde(default)]
    pub application_mode: Option<ApplicationMode>,
}

/// A source request's elapsed target: `none`, or `{elapsedMinutes: N}`.
#[derive(Debug)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema), schemars(untagged))]
pub enum TargetExpectation {
    Absent(NoTarget),
    Elapsed(ElapsedTarget),
}
registry_platform_yaml::shape_union!(TargetExpectation {
    scalar => Absent,
    mapping => Elapsed,
});

/// `none`: the request has no target.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum NoTarget {
    None,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ElapsedTarget {
    pub elapsed_minutes: BoundedU64<1, MAXIMUM_TARGET_ELAPSED_MINUTES>,
}

/// How the source applies an approved request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationMode {
    Manual,
    Automatic,
}

impl ApplicationMode {
    /// The value a source description's `onApproved.mode` carries.
    pub fn as_str(self) -> &'static str {
        match self {
            ApplicationMode::Manual => "manual",
            ApplicationMode::Automatic => "automatic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
kind: CaseworkFixture
id: professional-review-offline
request:
  source: professional-licences
  entity: scope-correction
expect:
  queue: corrections
  target:
    elapsedMinutes: 2880
";

    const SIMULATION: &str = "apiVersion: id.registrystack.org/formats/casework/simulation/v1alpha1
kind: CaseworkSimulation
id: friday-review
source: regional-register
holidayRevisions:
  office-holidays: 7
subject:
  entity: regional-correction
  recordId: request-0042
  version: \"1\"
  activity: review
  stage: technical
  fields:
    region: north
  stageEnteredAt: 2026-09-04T15:00:00+07:00
now: 2026-09-11T17:00:00+07:00
expect:
  queue: northern-review
  rule: northern-requests
  dueState: at-risk
  eligibleReminders: [due-soon]
";

    const HOLIDAY_SET: &str =
        "apiVersion: id.registrystack.org/formats/casework/holiday-set/v1alpha1
kind: CaseworkHolidaySet
holidaySet: office-holidays
revision: 7
dates: [2026-09-07]
";

    fn codes(report: &Report) -> Vec<(&str, &str)> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect()
    }

    #[test]
    fn each_offline_format_reads_through_the_shared_reader() {
        let fixture = CaseworkFixture::read("f.yaml", FIXTURE.as_bytes()).expect("fixture");
        assert!(matches!(
            fixture.value.expect.target,
            Some(TargetExpectation::Elapsed(ElapsedTarget { elapsed_minutes })) if elapsed_minutes.get() == 2880
        ));
        let simulation =
            CaseworkSimulation::read("s.yaml", SIMULATION.as_bytes()).expect("simulation");
        assert_eq!(simulation.value.expect.due_state, Some(DueState::AtRisk));
        assert_eq!(
            simulation.value.subject.routing_context().fields["region"],
            Value::from("north")
        );
        let holidays =
            CaseworkHolidaySet::read("h.yaml", HOLIDAY_SET.as_bytes()).expect("holiday set");
        assert_eq!(holidays.value.to_document().dates, ["2026-09-07"]);
    }

    #[test]
    fn cfg_yaml_6_a_byte_order_mark_is_accepted() {
        let bytes = [b"\xEF\xBB\xBF".as_slice(), HOLIDAY_SET.as_bytes()].concat();
        CaseworkHolidaySet::read("h.yaml", &bytes).expect("a BOM is accepted");
    }

    #[test]
    fn cfg_empty_6_target_none_states_no_target() {
        let text = FIXTURE.replace("  target:\n    elapsedMinutes: 2880\n", "  target: none\n");
        let fixture = CaseworkFixture::read("f.yaml", text.as_bytes()).expect("fixture");
        assert!(matches!(
            fixture.value.expect.target,
            Some(TargetExpectation::Absent(NoTarget::None))
        ));
        let null = FIXTURE.replace("  target:\n    elapsedMinutes: 2880\n", "  target:\n");
        let Err(report) = CaseworkFixture::read("f.yaml", null.as_bytes()) else {
            panic!("null refused");
        };
        assert_eq!(codes(&report), [("config.null-value", "/expect/target")]);
    }

    #[test]
    fn cfg_empty_1_a_null_simulated_field_is_refused_and_omission_states_it() {
        let null = SIMULATION.replace("    region: north\n", "    region: null\n");
        let Err(report) = CaseworkSimulation::read("s.yaml", null.as_bytes()) else {
            panic!("a null field value is refused");
        };
        assert_eq!(
            codes(&report),
            [("config.null-value", "/subject/fields/region")]
        );
        let empty = SIMULATION.replace("    region: north\n", "    region:\n");
        let Err(report) = CaseworkSimulation::read("s.yaml", empty.as_bytes()) else {
            panic!("an empty field value is refused");
        };
        assert_eq!(
            codes(&report),
            [("config.null-value", "/subject/fields/region")]
        );
        let list = SIMULATION.replace("    region: north\n", "    region: [north]\n");
        let Err(report) = CaseworkSimulation::read("s.yaml", list.as_bytes()) else {
            panic!("a list field value is refused");
        };
        assert_eq!(
            codes(&report),
            [("config.invalid-type", "/subject/fields/region")]
        );
        let omitted = SIMULATION.replace("  fields:\n    region: north\n", "");
        let simulation =
            CaseworkSimulation::read("s.yaml", omitted.as_bytes()).expect("omitted field");
        assert!(simulation.value.subject.routing_context().fields.is_empty());
        for (text, expected) in [
            ("true", Value::Bool(true)),
            ("3", Value::from(3)),
            ("2.5", Value::from(2.5)),
            ("\"north\"", Value::from("north")),
        ] {
            let scalar =
                SIMULATION.replace("    region: north\n", &format!("    region: {text}\n"));
            let simulation =
                CaseworkSimulation::read("s.yaml", scalar.as_bytes()).expect("scalar field");
            assert_eq!(
                simulation.value.subject.routing_context().fields["region"],
                expected
            );
        }
    }

    #[test]
    fn the_retired_fixture_spelling_names_each_replacement() {
        let old = "apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: x
";
        let Err(report) = CaseworkFixture::read("f.yaml", old.as_bytes()) else {
            panic!("retired");
        };
        assert_eq!(
            codes(&report),
            [("config.retired-api-version", "/apiVersion")]
        );
        let renamed = "apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
kind: CaseworkFixture
name: x
source:
  id: s
expect:
  queue: q
  targetElapsed: PT48H
";
        let Err(report) = CaseworkFixture::read("f.yaml", renamed.as_bytes()) else {
            panic!("removed keys");
        };
        let found = codes(&report);
        for path in ["/name", "/source", "/expect/targetElapsed"] {
            assert!(
                found.iter().any(|(_, at)| *at == path),
                "{path} in {found:?}"
            );
        }
    }

    #[test]
    fn a_fixture_tests_one_subject_and_only_its_expectations() {
        let neither = "apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
kind: CaseworkFixture
id: x
expect:
  queue: q
";
        let report = CaseworkFixture::read("f.yaml", neither.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("casework.fixture.no-subject", "")]);
        let review = "apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
kind: CaseworkFixture
id: x
review:
  kind: decision
  display: {summary: s}
expect:
  queue: q
  target: none
  applicationMode: manual
";
        let report = CaseworkFixture::read("f.yaml", review.as_bytes())
            .err()
            .unwrap();
        assert_eq!(
            codes(&report),
            [
                ("casework.fixture.request-expectation", "/expect/target"),
                (
                    "casework.fixture.request-expectation",
                    "/expect/applicationMode"
                ),
            ]
        );
        let both = format!("{FIXTURE}review:\n  kind: decision\n  display: {{}}\n");
        let report = CaseworkFixture::read("f.yaml", both.as_bytes())
            .err()
            .unwrap();
        assert_eq!(
            codes(&report),
            [("casework.fixture.two-subjects", "/request")]
        );
    }

    #[test]
    fn cfg_val_5_timestamps_carry_an_offset_and_dates_are_strict() {
        let local =
            SIMULATION.replace("now: 2026-09-11T17:00:00+07:00", "now: 2031-01-02T03:04:05");
        let report = CaseworkSimulation::read("s.yaml", local.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("config.invalid-value", "/now")]);
        assert!(!report.render_human().contains("2031-01-02"));
        let loose = HOLIDAY_SET.replace("2026-09-07", "2026-9-7");
        let report = CaseworkHolidaySet::read("h.yaml", loose.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("config.invalid-value", "/dates/0")]);
        let impossible = HOLIDAY_SET.replace("2026-09-07", "2026-02-30");
        let report = CaseworkHolidaySet::read("h.yaml", impossible.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("config.invalid-value", "/dates/0")]);
    }

    #[test]
    fn a_holiday_set_refuses_a_repeated_date_and_a_zero_revision() {
        let repeated = HOLIDAY_SET.replace("[2026-09-07]", "[2026-09-07, 2026-09-07]");
        let report = CaseworkHolidaySet::read("h.yaml", repeated.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("config.duplicate-item", "/dates/1")]);
        let zero = HOLIDAY_SET.replace("revision: 7", "revision: 0");
        let report = CaseworkHolidaySet::read("h.yaml", zero.as_bytes())
            .err()
            .unwrap();
        assert_eq!(codes(&report), [("config.out-of-range", "/revision")]);
    }

    #[test]
    fn a_holiday_set_holds_at_most_the_runtime_bound_of_dates() {
        let start = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
        let dates = (0..=MAXIMUM_HOLIDAY_SET_DATES as u64)
            .map(|offset| {
                (start + chrono::Days::new(offset))
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ");
        let text = HOLIDAY_SET.replace("[2026-09-07]", &format!("[{dates}]"));
        let report = CaseworkHolidaySet::read("h.yaml", text.as_bytes())
            .err()
            .unwrap();
        assert_eq!(
            codes(&report),
            [("casework.holiday-set.too-many-dates", "/dates")]
        );
    }

    #[test]
    fn a_file_in_another_kinds_directory_is_refused_at_its_kind() {
        let Err(report) = read_offline_file(
            "fixtures/s.yaml",
            SIMULATION.as_bytes(),
            OfflineFileKind::Fixture,
        ) else {
            panic!("a simulation under fixtures/ is refused");
        };
        assert_eq!(
            codes(&report),
            [("casework.project.misplaced-file", "/kind")]
        );
        assert!(read_offline_file(
            "simulations/s.yaml",
            SIMULATION.as_bytes(),
            OfflineFileKind::Simulation
        )
        .is_ok());
        let project = "apiVersion: id.registrystack.org/formats/casework/project/v1alpha1
kind: CaseworkProject
";
        let Err(report) = read_offline_file(
            "fixtures/p.yaml",
            project.as_bytes(),
            OfflineFileKind::Fixture,
        ) else {
            panic!("another kind is refused");
        };
        assert_eq!(codes(&report), [("config.wrong-kind", "/kind")]);
    }

    #[test]
    fn cfg_sec_2_an_offline_file_refuses_substitution() {
        let text = FIXTURE.replace("corrections", "${QUEUE}");
        let report = CaseworkFixture::read("f.yaml", text.as_bytes())
            .err()
            .unwrap();
        assert_eq!(
            codes(&report),
            [("config.substitution-not-allowed", "/expect/queue")]
        );
    }

    #[test]
    fn the_removed_simulation_members_name_their_replacements() {
        let text = SIMULATION
            .replace("recordId: request-0042", "id: request-0042")
            .replace("rule: northern-requests", "ruleId: northern-requests");
        let report = CaseworkSimulation::read("s.yaml", text.as_bytes())
            .err()
            .unwrap();
        let found = codes(&report);
        assert!(
            found.iter().any(|(_, at)| *at == "/subject/id"),
            "{found:?}"
        );
        assert!(
            found.iter().any(|(_, at)| *at == "/expect/ruleId"),
            "{found:?}"
        );
    }
}
