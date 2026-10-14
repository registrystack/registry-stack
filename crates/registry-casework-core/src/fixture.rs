//! Offline calendar input for pinned ReviewTask clocks.
use crate::HolidaySetDocument;
use chrono::{DateTime, NaiveDate, Utc};
use registry_platform_yaml::{
    ApiVersion, BoundedU64, Decoded, EnvelopeRule, Expect, FormatSpec, Invalid, LocalId, Reader,
    Report, UniqueList,
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
