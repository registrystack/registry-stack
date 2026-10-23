// SPDX-License-Identifier: Apache-2.0

//! The bounded exponential retry schedule every product's delivery uses.

/// The delays, in milliseconds, between consecutive attempts of one delivery:
/// `initial_ms`, then each delay multiplied by `multiplier` and capped at
/// `maximum_ms`. One delay sits between each pair of attempts, so the
/// schedule has `maximum_attempts - 1` entries and is empty for one attempt
/// or none.
#[must_use]
pub fn exponential_retry_delays_ms(
    initial_ms: u32,
    maximum_ms: u32,
    multiplier: u32,
    maximum_attempts: u8,
) -> Vec<u32> {
    let mut delay = initial_ms;
    (1..maximum_attempts)
        .map(|_| {
            let current = delay;
            delay = delay.saturating_mul(multiplier).min(maximum_ms);
            current
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::exponential_retry_delays_ms;

    #[test]
    fn the_schedule_doubles_to_its_ceiling_and_has_one_delay_per_retry() {
        assert_eq!(
            exponential_retry_delays_ms(1_000, 8_000, 2, 5),
            [1_000, 2_000, 4_000, 8_000]
        );
        assert_eq!(
            exponential_retry_delays_ms(30_000, 3_600_000, 2, 20).len(),
            19
        );
        assert_eq!(
            exponential_retry_delays_ms(30_000, 3_600_000, 2, 20)[7..9],
            [3_600_000, 3_600_000]
        );
    }

    #[test]
    fn one_attempt_or_none_has_no_delay() {
        assert!(exponential_retry_delays_ms(1_000, 8_000, 2, 1).is_empty());
        assert!(exponential_retry_delays_ms(1_000, 8_000, 2, 0).is_empty());
    }

    #[test]
    fn a_large_multiplier_saturates_at_the_ceiling() {
        assert_eq!(
            exponential_retry_delays_ms(u32::MAX - 1, u32::MAX, u32::MAX, 3),
            [u32::MAX - 1, u32::MAX]
        );
    }
}
