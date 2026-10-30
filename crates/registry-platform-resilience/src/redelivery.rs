//! The delay between one retry and the next.
//!
//! The first delay is the caller's `retry_delay`; each later one is the
//! previous delay, times `back_off_multiplier` when `use_exponential_back_off`
//! holds and the multiplier is above one, then varied by the caller's
//! collision-avoidance draw (a fraction of the delay plus or minus,
//! passed in as `variance`), then capped at `maximum_retry_delay`, so the
//! cap bounds the varied delay.

use std::time::Duration;

/// The knobs of the delay computation. The caller owns the retry
/// decision and the collision-avoidance draw; this carries only what
/// shapes the delay itself.
#[derive(Debug, Clone, Copy)]
pub struct RedeliveryDelayOptions {
    /// The first delay.
    pub retry_delay: Duration,
    /// The ceiling every later delay is bounded by.
    pub maximum_retry_delay: Duration,
    /// Whether a later delay grows from the previous one.
    pub use_exponential_back_off: bool,
    /// The growth factor, applied only with back-off on and a value
    /// above one.
    pub back_off_multiplier: f64,
}

/// The delay before the next retry, from the delay before the previous
/// one (`None` on the first). `variance` is the collision-avoidance
/// draw, a fraction of the delay plus or minus; zero draws the delay
/// unchanged.
#[must_use]
pub fn calculate_redelivery_delay(
    previous: Option<Duration>,
    options: &RedeliveryDelayOptions,
    variance: f64,
) -> Duration {
    let base = match previous {
        None => options.retry_delay.as_secs_f64(),
        Some(previous) => {
            let seconds = previous.as_secs_f64();
            // The multiplier grows the delay only with back-off on and a
            // multiplier above one.
            if options.use_exponential_back_off && options.back_off_multiplier > 1.0 {
                seconds * options.back_off_multiplier
            } else {
                seconds
            }
        }
    };
    let varied = base * (1.0 + variance);
    let capped = varied.min(options.maximum_retry_delay.as_secs_f64());
    Duration::from_secs_f64(capped.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seconds(delay: Duration) -> f64 {
        delay.as_secs_f64()
    }

    #[test]
    fn the_first_delay_is_the_retry_delay_whatever_the_growth() {
        let growing = RedeliveryDelayOptions {
            retry_delay: Duration::from_secs(2),
            maximum_retry_delay: Duration::from_secs(60),
            use_exponential_back_off: true,
            back_off_multiplier: 3.0,
        };
        assert_eq!(
            seconds(calculate_redelivery_delay(None, &growing, 0.25)),
            2.5
        );
        assert_eq!(
            seconds(calculate_redelivery_delay(None, &growing, -0.25)),
            1.5
        );
    }

    #[test]
    fn the_delay_grows_only_with_back_off_and_a_multiplier_above_one() {
        let flat = RedeliveryDelayOptions {
            retry_delay: Duration::from_secs(1),
            maximum_retry_delay: Duration::from_secs(60),
            use_exponential_back_off: false,
            back_off_multiplier: 3.0,
        };
        let previous = Duration::from_secs(1);
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &flat, 0.0)),
            1.0,
            "no back-off, no growth"
        );
        let unit = RedeliveryDelayOptions {
            use_exponential_back_off: true,
            back_off_multiplier: 1.0,
            ..flat
        };
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &unit, 0.0)),
            1.0,
            "a multiplier of one grows nothing"
        );
        let growing = RedeliveryDelayOptions {
            use_exponential_back_off: true,
            back_off_multiplier: 3.0,
            ..flat
        };
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &growing, 0.0)),
            3.0
        );
    }

    #[test]
    fn the_variance_applies_after_the_growth_and_the_cap_bounds_it() {
        let growing = RedeliveryDelayOptions {
            retry_delay: Duration::from_secs(1),
            maximum_retry_delay: Duration::from_secs(60),
            use_exponential_back_off: true,
            back_off_multiplier: 3.0,
        };
        // The second delay grows to three, then varies.
        assert_eq!(
            seconds(calculate_redelivery_delay(
                Some(Duration::from_secs(1)),
                &growing,
                0.15
            )),
            3.45
        );
        // The cap bounds the varied delay, not the delay before it.
        let capped = RedeliveryDelayOptions {
            maximum_retry_delay: Duration::from_secs(5),
            ..growing
        };
        assert_eq!(
            seconds(calculate_redelivery_delay(
                Some(Duration::from_secs(2)),
                &capped,
                0.5
            )),
            5.0,
            "three grown to four and a half, varied to six, capped at five"
        );
    }

    #[test]
    fn a_delay_sequence_follows_the_whole_order() {
        let options = RedeliveryDelayOptions {
            retry_delay: Duration::from_secs(1),
            maximum_retry_delay: Duration::from_secs(60),
            use_exponential_back_off: true,
            back_off_multiplier: 2.0,
        };
        let first = calculate_redelivery_delay(None, &options, 0.0);
        let second = calculate_redelivery_delay(Some(first), &options, 0.0);
        let third = calculate_redelivery_delay(Some(second), &options, 0.0);
        assert_eq!(
            [seconds(first), seconds(second), seconds(third)],
            [1.0, 2.0, 4.0]
        );
    }
}
