//! Typed offline review fixtures and calendar input for pinned ReviewTask clocks.
use crate::HolidaySetDocument;
use chrono::{DateTime, NaiveDate, Utc};
use registry_platform_yaml::{
    ApiVersion, BoundedU64, Decoded, EnvelopeRule, Expect, FormatSpec, Invalid, LocalId, Reader,
    Report, RetiredApiVersion, UniqueList,
};
use serde::{Deserialize, Deserializer};
use std::fmt;

pub const CASEWORK_HOLIDAY_SET_API_VERSION: &str =
    "id.registrystack.org/formats/casework/holiday-set/v1alpha1";
pub const CASEWORK_HOLIDAY_SET_KIND: &str = "CaseworkHolidaySet";
pub const MAXIMUM_HOLIDAY_SET_REVISION: u64 = i64::MAX as u64;
pub const MAXIMUM_HOLIDAY_SET_DATES: usize = 3660;
pub const CASEWORK_HOLIDAY_SET_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_HOLIDAY_SET_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_HOLIDAY_SET_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
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
        let decoded =
            Reader::new(file).decode::<Self>(bytes, &Expect::one(&CASEWORK_HOLIDAY_SET_FORMAT))?;
        let findings = decoded.value.findings();
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(crate::findings_report(&decoded.document, &findings))
        }
    }

    fn findings(&self) -> Vec<crate::ConfigFinding> {
        if self.dates.len() <= MAXIMUM_HOLIDAY_SET_DATES {
            return Vec::new();
        }
        vec![crate::ConfigFinding::new(
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

#[cfg(feature = "schema")]
impl schemars::JsonSchema for CalendarDate {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CalendarDate".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"})
    }
}

pub const CASEWORK_FIXTURE_API_VERSION: &str =
    "id.registrystack.org/formats/casework/fixture/v1alpha1";
pub const CASEWORK_FIXTURE_KIND: &str = "CaseworkFixture";
pub const CASEWORK_FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_FIXTURE_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/casework-fixture/v1alpha1",
            replacement: "Set apiVersion to id.registrystack.org/formats/casework/fixture/v1alpha1 and use the current review.policy and expect members.",
        }],
    },
    removed_keys: &[],
};

/// One synthetic context and meaningful expectations for a declared policy.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkFixture {
    pub api_version: String,
    pub kind: String,
    pub id: LocalId,
    pub review: CaseworkFixtureReview,
    pub expect: CaseworkFixtureExpect,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkFixtureReview {
    pub policy: LocalId,
    /// Business values remain JSON; the selected policy owns their schema.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-passthrough" = "Synthetic business fields are validated against the selected compiled ReviewPolicy displaySchema.")))]
    pub display: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("minProperties" = 1)))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkFixtureExpect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub outcomes: Option<UniqueList<LocalId>>,
}

struct FixtureLiteralText;
impl FixtureLiteralText {
    fn check(
        site: &registry_platform_yaml::ScalarSite<'_>,
    ) -> Result<(), registry_platform_yaml::Refusal> {
        if crate::config::contains_environment_expression(site.text) {
            return Err(registry_platform_yaml::Refusal {
                code: "config.substitution-not-allowed".into(),
                message: "a fixture is authored input and cannot substitute an environment value".into(),
                suggested_action: "Write literal synthetic fixture values; bind deployment values in runtime.yaml.".into(),
            });
        }
        Ok(())
    }
}
impl registry_platform_yaml::ScalarHook for FixtureLiteralText {
    fn key(
        &mut self,
        site: &registry_platform_yaml::ScalarSite<'_>,
    ) -> Result<(), registry_platform_yaml::Refusal> {
        Self::check(site)
    }
    fn value(
        &mut self,
        site: &registry_platform_yaml::ScalarSite<'_>,
    ) -> Result<Option<String>, registry_platform_yaml::Refusal> {
        Self::check(site).map(|()| None)
    }
}

impl CaseworkFixture {
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = FixtureLiteralText;
        let decoded = Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&CASEWORK_FIXTURE_FORMAT))?;
        let mut findings = Vec::new();
        if decoded.value.expect.queue.is_none() && decoded.value.expect.outcomes.is_none() {
            findings.push(crate::ConfigFinding::new(
                "casework.fixture.expectation-required",
                "/expect",
                "expected a queue or a nonempty outcome list",
                "Declare at least one expectation the fixture must prove.",
            ));
        }
        if decoded
            .value
            .expect
            .outcomes
            .as_ref()
            .is_some_and(|items| items.is_empty())
        {
            findings.push(crate::ConfigFinding::new(
                "casework.fixture.empty-outcomes",
                "/expect/outcomes",
                "expected at least one outcome identifier",
                "List the policy's configured outcomes, or omit outcomes and assert a queue.",
            ));
        }
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(crate::findings_report(&decoded.document, &findings))
        }
    }

    /// Validate the synthetic display under the exact compiled policy closure.
    /// Queue expectations name the first stage queue; no source/runtime is read.
    pub fn read_against(
        file: &str,
        bytes: &[u8],
        project: &crate::CaseworkProject,
    ) -> Result<Decoded<Self>, Report> {
        let decoded = Self::read(file, bytes)?;
        let fixture = &decoded.value;
        let mut findings = Vec::new();
        let selected = project
            .review_policies
            .iter()
            .find(|policy| policy.id == fixture.review.policy.as_str());
        if let Some(policy) = selected {
            match project.compile_policy(fixture.review.policy.as_str()) {
                Ok(closure) => {
                    let display = serde_json::Value::Object(
                        fixture.review.display.clone().into_iter().collect(),
                    );
                    if let Err(error) = closure.validate_display(&display) {
                        let pointer = match &error {
                            crate::ReviewDecisionValidationError::Structured(error) => format!(
                                "/review/display{}",
                                error.path.strip_prefix("$.display").unwrap_or("")
                            ),
                            crate::ReviewDecisionValidationError::Policy(_) => {
                                "/review/policy".into()
                            }
                        };
                        findings.push(crate::ConfigFinding::new(
                            "casework.fixture.display-invalid", pointer,
                            "the synthetic display does not satisfy the compiled review policy",
                            "Correct the fixture display against the selected policy's bounded display schema.",
                        ));
                    }
                }
                Err(_) => findings.push(crate::ConfigFinding::new(
                    "casework.fixture.policy-invalid",
                    "/review/policy",
                    "the selected review policy cannot compile",
                    "Correct the authored project before testing its fixtures.",
                )),
            }
            if let Some(expected) = &fixture.expect.outcomes {
                let actual = policy
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.id.as_str())
                    .collect::<Vec<_>>();
                let mut unknown = false;
                for (index, outcome) in expected.iter().enumerate() {
                    if !actual.contains(&outcome.as_str()) {
                        unknown = true;
                        findings.push(crate::ConfigFinding::new(
                            "casework.fixture.unknown-outcome",
                            format!("/expect/outcomes/{index}"),
                            "the outcome is not declared by the selected policy",
                            "Name an outcome declared under the selected review policy.",
                        ));
                    }
                }
                if !unknown && expected.iter().map(LocalId::as_str).collect::<Vec<_>>() != actual {
                    findings.push(crate::ConfigFinding::new(
                        "casework.fixture.outcomes-mismatch",
                        "/expect/outcomes",
                        "the expected outcomes differ from the policy's configured outcomes",
                        "List every configured outcome in policy order.",
                    ));
                }
            }
        } else {
            findings.push(crate::ConfigFinding::new(
                "casework.fixture.unknown-policy",
                "/review/policy",
                "the review policy is not declared in the project",
                "Name a policy declared under reviewPolicies.",
            ));
        }
        if let Some(queue) = &fixture.expect.queue {
            if !project
                .queues
                .iter()
                .any(|declared| declared.id == queue.as_str())
            {
                findings.push(crate::ConfigFinding::new(
                    "casework.fixture.unknown-queue",
                    "/expect/queue",
                    "the expected queue is not declared in the project",
                    "Name a queue declared under queues.",
                ));
            } else if selected.is_some_and(|policy| {
                policy
                    .stages
                    .first()
                    .is_none_or(|stage| stage.queue != queue.as_str())
            }) {
                findings.push(crate::ConfigFinding::new(
                    "casework.fixture.queue-mismatch",
                    "/expect/queue",
                    "the expected queue differs from the policy's first stage queue",
                    "Assert the queue declared by the first review stage.",
                ));
            }
        }
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(crate::findings_report(&decoded.document, &findings))
        }
    }
}
