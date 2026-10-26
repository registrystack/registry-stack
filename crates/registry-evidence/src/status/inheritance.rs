//! Whether a new allocation inherits an observed status, and whether a later
//! input is older than what the allocation's evaluation already read.
//!
//! A hook processed between Evidence's source read and the allocation commit
//! finds no allocation, so intake keeps the latest observation per
//! requirement and pseudonym. A new allocation inherits that status only
//! when it is not VALID and was captured after the evaluation's source read
//! less the clock-skew allowance.
//!
//! An allocation stores its source read rounded down to the hour, which keeps
//! an exact extract `publishedAt` out of the ledger. A hook or reconciliation
//! input whose source time is earlier than that hour less the clock-skew
//! allowance is stale for the entry. Rounding down errs toward applying,
//! never discarding, newer input.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Timelike, Utc};

use super::transition::EntryStatus;

/// When the evaluation behind an allocation read its source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SourceRead {
    /// An extract source: its `publishedAt` and the instant the evaluation
    /// read it.
    Extract {
        published_at: DateTime<Utc>,
        evaluation_instant: DateTime<Utc>,
    },
    /// An HTTP source, read at request time.
    Http { request_time: DateTime<Utc> },
}

impl SourceRead {
    /// The instant the source counts as read: the earlier of `publishedAt`
    /// and the evaluation instant for an extract, so a future-dated
    /// `publishedAt` never counts as later than the instant it is read, and
    /// the request time for HTTP.
    #[must_use]
    pub fn instant(&self) -> DateTime<Utc> {
        match self {
            Self::Extract {
                published_at,
                evaluation_instant,
            } => (*published_at).min(*evaluation_instant),
            Self::Http { request_time } => *request_time,
        }
    }

    /// The source read instant rounded down to the hour, as an allocation
    /// stores it.
    #[must_use]
    pub fn read_hour(&self) -> Option<DateTime<Utc>> {
        self.instant()
            .with_minute(0)
            .and_then(|instant| instant.with_second(0))
            .and_then(|instant| instant.with_nanosecond(0))
    }
}

/// Whether an input with `source_time` predates an entry's source read: it is
/// earlier than the stored read hour less the clock-skew allowance. A skew
/// too large to subtract makes no input stale.
#[must_use]
pub(crate) fn predates_source_read(
    source_time: DateTime<Utc>,
    read_hour: DateTime<Utc>,
    clock_skew: Duration,
) -> bool {
    TimeDelta::from_std(clock_skew)
        .ok()
        .and_then(|skew| read_hour.checked_sub_signed(skew))
        .is_some_and(|threshold| source_time < threshold)
}

// `publishedAt` is extract metadata and never reaches logs or diagnostics.
impl fmt::Debug for SourceRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Extract { .. } => "SourceRead::Extract([REDACTED])",
            Self::Http { .. } => "SourceRead::Http([REDACTED])",
        })
    }
}

/// The latest observed status for one pseudonym and the source capture time
/// of the change that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedStatus {
    pub status: EntryStatus,
    pub captured_at: DateTime<Utc>,
}

/// The status a new allocation starts with.
#[must_use]
pub fn inherited_status(
    observation: Option<ObservedStatus>,
    source_read: SourceRead,
    clock_skew: Duration,
) -> EntryStatus {
    let Some(observation) = observation else {
        return EntryStatus::Valid;
    };
    if observation.status == EntryStatus::Valid {
        return EntryStatus::Valid;
    }
    // A skew too large to subtract reaches back before any capture time, so
    // every non-VALID observation is inherited.
    let threshold = TimeDelta::from_std(clock_skew)
        .ok()
        .and_then(|skew| source_read.instant().checked_sub_signed(skew));
    match threshold {
        Some(threshold) if observation.captured_at <= threshold => EntryStatus::Valid,
        _ => observation.status,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{DateTime, TimeDelta, TimeZone, Utc};

    use super::{inherited_status, predates_source_read, ObservedStatus, SourceRead};
    use crate::status::{EntryStatus, DEFAULT_CLOCK_SKEW};

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
    }

    fn observed(status: EntryStatus, captured_at: DateTime<Utc>) -> Option<ObservedStatus> {
        Some(ObservedStatus {
            status,
            captured_at,
        })
    }

    const SKEW_SECONDS: i64 = 600;

    #[test]
    fn the_source_read_is_the_earlier_of_published_at_and_the_evaluation_instant() {
        let read = SourceRead::Extract {
            published_at: at(-100),
            evaluation_instant: at(0),
        };
        assert_eq!(read.instant(), at(-100));
        let future_dated = SourceRead::Extract {
            published_at: at(100),
            evaluation_instant: at(0),
        };
        assert_eq!(future_dated.instant(), at(0));
        assert_eq!(
            SourceRead::Http {
                request_time: at(5)
            }
            .instant(),
            at(5)
        );
    }

    #[test]
    fn a_non_valid_observation_captured_after_the_read_less_skew_is_inherited() {
        for status in [EntryStatus::Suspended, EntryStatus::Invalid] {
            for read in [
                SourceRead::Http {
                    request_time: at(0),
                },
                SourceRead::Extract {
                    published_at: at(0),
                    evaluation_instant: at(3_600),
                },
            ] {
                let just_after = at(-SKEW_SECONDS) + TimeDelta::milliseconds(1);
                assert_eq!(
                    inherited_status(observed(status, just_after), read, DEFAULT_CLOCK_SKEW),
                    status
                );
                assert_eq!(
                    inherited_status(observed(status, at(1_000)), read, DEFAULT_CLOCK_SKEW),
                    status
                );
            }
        }
    }

    #[test]
    fn an_observation_captured_at_or_before_the_read_less_skew_is_not_inherited() {
        let read = SourceRead::Http {
            request_time: at(0),
        };
        for captured_at in [at(-SKEW_SECONDS), at(-SKEW_SECONDS - 1), at(-86_400)] {
            assert_eq!(
                inherited_status(
                    observed(EntryStatus::Invalid, captured_at),
                    read,
                    DEFAULT_CLOCK_SKEW
                ),
                EntryStatus::Valid
            );
        }
    }

    #[test]
    fn a_future_dated_published_at_does_not_move_the_read_later() {
        // Read at the evaluation instant (0), not at the future publishedAt
        // (+7200): an observation at -300 is after 0 less the skew.
        let read = SourceRead::Extract {
            published_at: at(7_200),
            evaluation_instant: at(0),
        };
        assert_eq!(
            inherited_status(
                observed(EntryStatus::Suspended, at(-300)),
                read,
                DEFAULT_CLOCK_SKEW
            ),
            EntryStatus::Suspended
        );
        // An extract published earlier anchors the read on its publishedAt.
        let read = SourceRead::Extract {
            published_at: at(-7_200),
            evaluation_instant: at(0),
        };
        assert_eq!(
            inherited_status(
                observed(EntryStatus::Suspended, at(-7_200 - SKEW_SECONDS)),
                read,
                DEFAULT_CLOCK_SKEW
            ),
            EntryStatus::Valid
        );
        assert_eq!(
            inherited_status(
                observed(EntryStatus::Suspended, at(-7_200 - SKEW_SECONDS + 1)),
                read,
                DEFAULT_CLOCK_SKEW
            ),
            EntryStatus::Suspended
        );
    }

    #[test]
    fn a_valid_observation_or_none_starts_the_allocation_valid() {
        let read = SourceRead::Http {
            request_time: at(0),
        };
        assert_eq!(
            inherited_status(
                observed(EntryStatus::Valid, at(10)),
                read,
                DEFAULT_CLOCK_SKEW
            ),
            EntryStatus::Valid
        );
        assert_eq!(
            inherited_status(None, read, DEFAULT_CLOCK_SKEW),
            EntryStatus::Valid
        );
    }

    #[test]
    fn a_zero_skew_compares_with_the_read_itself() {
        let read = SourceRead::Http {
            request_time: at(0),
        };
        assert_eq!(
            inherited_status(observed(EntryStatus::Invalid, at(0)), read, Duration::ZERO),
            EntryStatus::Valid
        );
        assert_eq!(
            inherited_status(observed(EntryStatus::Invalid, at(1)), read, Duration::ZERO),
            EntryStatus::Invalid
        );
    }

    #[test]
    fn an_unrepresentable_skew_inherits_every_non_valid_observation() {
        let read = SourceRead::Http {
            request_time: at(0),
        };
        assert_eq!(
            inherited_status(
                observed(EntryStatus::Suspended, at(-1_000_000_000)),
                read,
                Duration::MAX
            ),
            EntryStatus::Suspended
        );
    }

    #[test]
    fn debug_output_never_carries_published_at() {
        let read = SourceRead::Extract {
            published_at: at(12_345),
            evaluation_instant: at(0),
        };
        let rendered = format!("{read:?}");
        assert!(!rendered.contains(&at(12_345).to_string()), "{rendered}");
        assert!(!rendered.contains("2027"), "{rendered}");
        assert!(!rendered.contains("1800012345"), "{rendered}");
    }

    #[test]
    fn an_allocation_stores_its_source_read_rounded_down_to_the_hour() {
        let read = SourceRead::Extract {
            published_at: at(1_049) + TimeDelta::milliseconds(250),
            evaluation_instant: at(5_000),
        };
        assert_eq!(read.read_hour(), Some(at(0)));
        let read = SourceRead::Http {
            request_time: at(3_599),
        };
        assert_eq!(read.read_hour(), Some(at(0)));
        let read = SourceRead::Http {
            request_time: at(3_600),
        };
        assert_eq!(read.read_hour(), Some(at(3_600)));
        let read = SourceRead::Http {
            request_time: at(-1),
        };
        assert_eq!(read.read_hour(), Some(at(-3_600)));
    }

    #[test]
    fn an_input_earlier_than_the_read_hour_less_skew_predates_the_read() {
        let read_hour = at(0);
        assert!(predates_source_read(
            at(-SKEW_SECONDS) - TimeDelta::milliseconds(1),
            read_hour,
            DEFAULT_CLOCK_SKEW
        ));
        for source_time in [at(-SKEW_SECONDS), at(-1), at(0), at(1_800)] {
            assert!(!predates_source_read(
                source_time,
                read_hour,
                DEFAULT_CLOCK_SKEW
            ));
        }
        // A skew too large to subtract makes no input stale.
        assert!(!predates_source_read(
            DateTime::<Utc>::MIN_UTC,
            read_hour,
            Duration::MAX
        ));
    }
}
