//! The observation retention floor.
//!
//! An observation must outlive every evaluation that read the source before
//! it. An evaluation from an extract can commit an allocation as late as the
//! extract's maximum age after its publication, so the floor is anchored on
//! that age; a requirement with only HTTP sources commits within the signing
//! transaction deadline of its request.

use std::time::Duration;

use thiserror::Error;

/// The shortest observation retention a deployment may configure.
///
/// With extract sources: the largest `maximumExtractAgeSeconds` among the
/// evaluation sources of status-required requirements, plus the clock-skew
/// allowance. With only HTTP sources: the signing transaction deadline plus
/// the clock-skew allowance.
#[must_use]
pub fn retention_floor(
    largest_maximum_extract_age: Duration,
    signing_deadline: Duration,
    clock_skew: Duration,
    has_extract_sources: bool,
) -> Duration {
    let anchor = if has_extract_sources {
        largest_maximum_extract_age
    } else {
        signing_deadline
    };
    anchor.saturating_add(clock_skew)
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
    fn extract_sources_anchor_the_floor_on_the_largest_maximum_extract_age() {
        assert_eq!(
            retention_floor(
                SIX_HOURS,
                DEFAULT_SIGNING_TRANSACTION_DEADLINE,
                DEFAULT_CLOCK_SKEW,
                true
            ),
            Duration::from_secs(6 * 60 * 60 + 10 * 60)
        );
    }

    #[test]
    fn http_only_sources_anchor_the_floor_on_the_signing_deadline() {
        assert_eq!(
            retention_floor(
                SIX_HOURS,
                DEFAULT_SIGNING_TRANSACTION_DEADLINE,
                DEFAULT_CLOCK_SKEW,
                false
            ),
            Duration::from_secs(20 + 10 * 60)
        );
    }

    #[test]
    fn a_floor_that_would_overflow_saturates() {
        assert_eq!(
            retention_floor(Duration::MAX, Duration::ZERO, Duration::from_secs(1), true),
            Duration::MAX
        );
    }

    #[test]
    fn retention_below_the_floor_is_refused_and_at_the_floor_accepted() {
        let floor = retention_floor(
            SIX_HOURS,
            DEFAULT_SIGNING_TRANSACTION_DEADLINE,
            DEFAULT_CLOCK_SKEW,
            true,
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
                configured_seconds: 22_199,
                floor_seconds: 22_200,
            })
        );
        assert_eq!(
            refused.unwrap_err().to_string(),
            "the observation retention of 22199 s is below its floor of 22200 s"
        );
        assert!(check_observation_retention(floor - Duration::from_millis(1), floor).is_err());
    }
}
