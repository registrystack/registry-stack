//! What a transition request carries: the target status, a reason category,
//! the closed provenance of its cause and, for a mapped cause, the source
//! time of its input.

use std::fmt;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::error::StatusError;
use super::ledger::StatusEntry;
use super::transition::{EntryStatus, Refusal, TransitionCause};

/// Longest accepted provenance text, in bytes.
const MAXIMUM_PROVENANCE_TEXT_BYTES: usize = 256;

/// Longest accepted reason category, in bytes.
const MAXIMUM_REASON_CATEGORY_BYTES: usize = 64;

/// Most operator principals one transition names.
const MAXIMUM_OPERATOR_PRINCIPALS: usize = 16;

/// The version of a service's mapping rules. Versions are at most
/// `i32::MAX`, the largest the ledger stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappingVersion(u32);

impl MappingVersion {
    pub fn new(version: u32) -> Result<Self, StatusError> {
        if version == 0 || i32::try_from(version).is_err() {
            return Err(StatusError::InvalidInput(
                "a mapping version must be between 1 and 2147483647",
            ));
        }
        Ok(Self(version))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The stored form; [`Self::new`] keeps it in range.
    pub(crate) fn column(self) -> i32 {
        i32::try_from(self.0).unwrap_or(i32::MAX)
    }

    /// A version read back from the ledger.
    pub(crate) fn from_column(version: i32) -> Result<Self, StatusError> {
        u32::try_from(version)
            .map_err(|_| StatusError::InvalidInput("stored mapping version is negative"))
            .and_then(Self::new)
    }
}

/// A source record revision, as a hook or an extract row carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceRevision(i64);

impl SourceRevision {
    pub fn new(revision: i64) -> Result<Self, StatusError> {
        if revision <= 0 {
            return Err(StatusError::InvalidInput(
                "a source revision must be positive",
            ));
        }
        Ok(Self(revision))
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// A provenance value: an event id, a package revision, an event source, an
/// operator principal or a case reference. 1 to 256 bytes with no control
/// characters. `Debug` shows its length only, so a value never reaches logs
/// through a formatted request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProvenanceText(String);

impl ProvenanceText {
    pub fn new(value: &str) -> Result<Self, StatusError> {
        let valid = (1..=MAXIMUM_PROVENANCE_TEXT_BYTES).contains(&value.len())
            && !value.chars().any(char::is_control);
        if !valid {
            return Err(StatusError::InvalidInput(
                "a provenance value must be 1 to 256 bytes with no control characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProvenanceText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ProvenanceText({} bytes)", self.0.len())
    }
}

/// A reason category from the deployment's closed list: a lower-case ASCII
/// letter, then up to 63 lower-case letters, digits or hyphens.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReasonCategory(String);

impl ReasonCategory {
    pub fn new(value: &str) -> Result<Self, StatusError> {
        let valid = (1..=MAXIMUM_REASON_CATEGORY_BYTES).contains(&value.len())
            && value
                .bytes()
                .next()
                .is_some_and(|first| first.is_ascii_lowercase())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(StatusError::InvalidInput(
                "a reason category must be a lower-case letter then up to 63 lower-case \
                 letters, digits or hyphens",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a transition came from: one closed shape per cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// A verified hook delivery.
    Hook {
        mapping_version: MappingVersion,
        event_id: ProvenanceText,
        revision: SourceRevision,
        package_revision: ProvenanceText,
        source: ProvenanceText,
    },
    /// An operator action, with every principal that approved it.
    Operator {
        principals: Vec<ProvenanceText>,
        case_reference: ProvenanceText,
    },
    /// A complete reconciliation run. `revision` is the matched row's
    /// revision; an absence has none.
    Reconciliation {
        mapping_version: MappingVersion,
        run_id: Uuid,
        extract_digest: [u8; 32],
        revision: Option<SourceRevision>,
    },
}

impl Provenance {
    #[must_use]
    pub const fn cause(&self) -> TransitionCause {
        match self {
            Self::Hook { .. } => TransitionCause::Hook,
            Self::Operator { .. } => TransitionCause::Operator,
            Self::Reconciliation { .. } => TransitionCause::Reconciliation,
        }
    }

    /// The mapping version a mapped cause applies under; operators use none.
    #[must_use]
    pub const fn mapping_version(&self) -> Option<MappingVersion> {
        match self {
            Self::Hook {
                mapping_version, ..
            }
            | Self::Reconciliation {
                mapping_version, ..
            } => Some(*mapping_version),
            Self::Operator { .. } => None,
        }
    }

    /// The source revision the request reflects, if it has one.
    #[must_use]
    pub const fn revision(&self) -> Option<SourceRevision> {
        match self {
            Self::Hook { revision, .. } => Some(*revision),
            Self::Reconciliation { revision, .. } => *revision,
            Self::Operator { .. } => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StatusError> {
        if let Self::Operator { principals, .. } = self {
            if principals.is_empty() || principals.len() > MAXIMUM_OPERATOR_PRINCIPALS {
                return Err(StatusError::InvalidInput(
                    "an operator transition names 1 to 16 principals",
                ));
            }
            for (position, principal) in principals.iter().enumerate() {
                if principals[..position].contains(principal) {
                    return Err(StatusError::InvalidInput(
                        "an operator transition names each principal once",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// When the source produced a hook or reconciliation input: the hook's
/// CloudEvent `time` or the extract's `publishedAt`. The ledger compares it
/// with an entry's source read and never stores it, and `Debug` never shows
/// it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SourceTime(DateTime<Utc>);

impl SourceTime {
    #[must_use]
    pub const fn new(instant: DateTime<Utc>) -> Self {
        Self(instant)
    }

    #[must_use]
    pub const fn instant(&self) -> DateTime<Utc> {
        self.0
    }
}

impl fmt::Debug for SourceTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceTime([REDACTED])")
    }
}

/// One request to move a status entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionRequest {
    pub entry: StatusEntry,
    pub to: EntryStatus,
    pub reason: ReasonCategory,
    pub provenance: Provenance,
    /// The source time of a hook or reconciliation input; an operator
    /// request has none.
    pub source_time: Option<SourceTime>,
}

impl TransitionRequest {
    pub(crate) fn validate(&self) -> Result<(), StatusError> {
        self.provenance.validate()?;
        match (self.provenance.cause(), self.source_time) {
            (TransitionCause::Operator, Some(_)) => Err(StatusError::InvalidInput(
                "an operator transition has no source time",
            )),
            (TransitionCause::Hook | TransitionCause::Reconciliation, None) => {
                Err(StatusError::InvalidInput(
                    "a hook or reconciliation transition names its source time",
                ))
            }
            _ => Ok(()),
        }
    }
}

/// What a transition request did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// The entry moved and the transitions table records it.
    Applied {
        transition_id: Uuid,
        from: EntryStatus,
        to: EntryStatus,
    },
    /// The entry already held the status. A newer source revision is still
    /// recorded, so older deliveries become stale.
    Unchanged(EntryStatus),
    /// The request reflects a source revision older than the last applied
    /// one, so it changes nothing.
    StaleRevision,
    /// The request's source time is earlier than the entry's source read
    /// less the clock-skew allowance: the evaluation behind the entry read a
    /// newer source state, so the request changes nothing.
    StaleSource,
    /// The transition table refuses the request; nothing changed.
    Refused(Refusal),
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{
        MappingVersion, Provenance, ProvenanceText, ReasonCategory, SourceRevision, SourceTime,
    };

    fn text(value: &str) -> ProvenanceText {
        ProvenanceText::new(value).unwrap()
    }

    #[test]
    fn provenance_values_refuse_what_the_ledger_cannot_store() {
        assert!(MappingVersion::new(0).is_err());
        assert!(MappingVersion::new(1).is_ok());
        assert!(MappingVersion::new(2_147_483_647).is_ok());
        assert!(MappingVersion::new(2_147_483_648).is_err());
        assert_eq!(MappingVersion::from_column(7).unwrap().get(), 7);
        assert!(MappingVersion::from_column(-1).is_err());
        assert!(SourceRevision::new(0).is_err());
        assert!(SourceRevision::new(1).is_ok());
        assert!(ProvenanceText::new("").is_err());
        assert!(ProvenanceText::new(&"a".repeat(256)).is_ok());
        assert!(ProvenanceText::new(&"a".repeat(257)).is_err());
        assert!(ProvenanceText::new("line\nbreak").is_err());
        assert!(ProvenanceText::new("tab\there").is_err());
        assert!(ReasonCategory::new("lost-device").is_ok());
        assert!(ReasonCategory::new(&format!("a{}", "b".repeat(63))).is_ok());
        assert!(ReasonCategory::new(&format!("a{}", "b".repeat(64))).is_err());
        for invalid in [
            "",
            "Lost-device",
            "-lost",
            "1lost",
            "lost device",
            "lost_device",
        ] {
            assert!(ReasonCategory::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_source_time_never_formats() {
        let source_time = SourceTime::new(Utc.with_ymd_and_hms(2026, 10, 19, 3, 17, 29).unwrap());
        assert_eq!(format!("{source_time:?}"), "SourceTime([REDACTED])");
    }

    #[test]
    fn provenance_text_debug_shows_only_the_length() {
        assert_eq!(
            format!("{:?}", text("operator-a")),
            "ProvenanceText(10 bytes)"
        );
    }

    #[test]
    fn operator_provenance_names_each_principal_once() {
        let operator = |principals: Vec<ProvenanceText>| Provenance::Operator {
            principals,
            case_reference: text("case-1"),
        };
        assert!(operator(vec![text("a")]).validate().is_ok());
        assert!(operator(Vec::new()).validate().is_err());
        assert!(operator(vec![text("a"), text("a")]).validate().is_err());
        assert!(operator((0..17).map(|n| text(&n.to_string())).collect())
            .validate()
            .is_err());
    }
}
