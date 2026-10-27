//! The observation retention floor.
//!
//! An observation must outlive every evaluation that read the source before
//! it. An evaluation from an extract can read it as late as the extract's
//! maximum age after its publication and then commit an allocation as late
//! as the signing transaction deadline after that, so the floor adds both; a
//! requirement with only HTTP sources has no extract age to add.

use std::time::Duration;

use thiserror::Error;

/// The shortest observation retention a deployment may configure.
///
/// The largest `maximumExtractAgeSeconds` among the evaluation sources of
/// status-required requirements (zero with only HTTP sources), plus the
/// signing transaction deadline, plus the clock-skew allowance.
#[must_use]
pub fn retention_floor(
    largest_maximum_extract_age: Duration,
    signing_deadline: Duration,
    clock_skew: Duration,
) -> Duration {
    largest_maximum_extract_age
        .saturating_add(signing_deadline)
        .saturating_add(clock_skew)
}

/// A configured observation retention below its floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error(
    "the observation retention of {configured_seconds} s is below its floor of {floor_seconds} s"
)]
pub struct RetentionBelowFloor {
    pub configured_seconds: u64,
    pub floor_seconds: u64,
}

/// Refuse a configured observation retention below the floor. A retention
/// equal to the floor is accepted.
pub fn check_observation_retention(
    configured: Duration,
    floor: Duration,
) -> Result<(), RetentionBelowFloor> {
    if configured < floor {
        return Err(RetentionBelowFloor {
            configured_seconds: configured.as_secs(),
            floor_seconds: floor.as_secs(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{check_observation_retention, retention_floor, RetentionBelowFloor};
    use crate::status::{DEFAULT_CLOCK_SKEW, DEFAULT_SIGNING_TRANSACTION_DEADLINE};

    const SIX_HOURS: Duration = Duration::from_secs(6 * 60 * 60);

    #[test]
    fn the_floor_adds_the_signing_deadline_and_skew_to_the_largest_extract_age() {
        assert_eq!(
            retention_floor(
                SIX_HOURS,
                DEFAULT_SIGNING_TRANSACTION_DEADLINE,
                DEFAULT_CLOCK_SKEW,
            ),
            Duration::from_secs(6 * 60 * 60 + 20 + 10 * 60)
        );
    }

    #[test]
    fn http_only_sources_have_no_extract_age_to_add() {
        assert_eq!(
            retention_floor(
                Duration::ZERO,
                DEFAULT_SIGNING_TRANSACTION_DEADLINE,
                DEFAULT_CLOCK_SKEW,
            ),
            Duration::from_secs(20 + 10 * 60)
        );
    }

    #[test]
    fn an_extract_age_below_the_signing_deadline_still_counts_both() {
        assert_eq!(
            retention_floor(
                Duration::from_secs(5),
                DEFAULT_SIGNING_TRANSACTION_DEADLINE,
                DEFAULT_CLOCK_SKEW,
            ),
            Duration::from_secs(5 + 20 + 10 * 60)
        );
    }

    #[test]
    fn a_floor_that_would_overflow_saturates() {
        assert_eq!(
            retention_floor(Duration::MAX, Duration::ZERO, Duration::from_secs(1)),
            Duration::MAX
        );
        assert_eq!(
            retention_floor(Duration::from_secs(1), Duration::MAX, Duration::ZERO),
            Duration::MAX
        );
    }

    #[test]
    fn retention_below_the_floor_is_refused_and_at_the_floor_accepted() {
        let floor = retention_floor(
            SIX_HOURS,
            DEFAULT_SIGNING_TRANSACTION_DEADLINE,
            DEFAULT_CLOCK_SKEW,
        );
        assert_eq!(check_observation_retention(floor, floor), Ok(()));
        assert_eq!(
            check_observation_retention(floor + Duration::from_secs(1), floor),
            Ok(())
        );
        let refused = check_observation_retention(floor - Duration::from_secs(1), floor);
        assert_eq!(
            refused,
            Err(RetentionBelowFloor {
                configured_seconds: 22_219,
                floor_seconds: 22_220,
            })
        );
        assert_eq!(
            refused.unwrap_err().to_string(),
            "the observation retention of 22219 s is below its floor of 22220 s"
        );
        assert!(check_observation_retention(floor - Duration::from_millis(1), floor).is_err());
    }
}
