// SPDX-License-Identifier: Apache-2.0

//! The redelivery delay computation of `RedeliveryPolicy` at the pinned
//! tag (`products/adapter/CONCEPT.md` section 8.7,
//! `RedeliveryPolicy.calculateRedeliveryDelay`): the first delay is
//! `retryDelaySeconds`, each later one the previous delay (times the
//! multiplier when backing off), then the collision variance, then the
//! `maximumRetryDelaySeconds` cap, so the cap bounds the varied delay.

use std::time::Duration;

use registry_adapter_core::RedeliveryOptions;

/// The delay before the next redelivery, from the delay before the
/// previous one (`None` on the first). `variance` is the
/// collision-avoidance draw, a fraction of the delay plus or minus
/// ([`draw_variance`]); zero when the policy does not ask for it.
pub(crate) fn calculate_redelivery_delay(
    previous: Option<Duration>,
    policy: &RedeliveryOptions,
    variance: f64,
) -> Duration {
    let base = match previous {
        None => f64::from(policy.retry_delay_seconds.get()),
        Some(previous) => {
            let seconds = previous.as_secs_f64();
            // The multiplier grows the delay only with back-off on and a
            // multiplier above 1, as at the pinned tag.
            if policy.use_exponential_back_off && policy.back_off_multiplier > 1.0 {
                seconds * policy.back_off_multiplier
            } else {
                seconds
            }
        }
    };
    let varied = base * (1.0 + variance);
    let capped = varied.min(f64::from(policy.maximum_retry_delay_seconds.get()));
    Duration::from_secs_f64(capped.max(0.0))
}

/// One collision-avoidance draw: a uniform fraction of the delay, plus
/// or minus up to the factor, when the policy asks for it and none
/// otherwise.
pub(crate) fn draw_variance(policy: &RedeliveryOptions) -> f64 {
    if !policy.use_collision_avoidance {
        return 0.0;
    }
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system supplies randomness");
    // Fifty-three random bits as one uniform draw in [0, 1), centered
    // and scaled into [-factor, factor).
    let unit = (u64::from_le_bytes(bytes) >> 11) as f64 / 9_007_199_254_740_992.0;
    (unit * 2.0 - 1.0) * policy.collision_avoidance_factor
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(members: serde_json::Value) -> RedeliveryOptions {
        serde_json::from_value(members).expect("the policy parses")
    }

    fn seconds(delay: Duration) -> f64 {
        delay.as_secs_f64()
    }

    #[test]
    fn the_first_delay_is_the_retry_delay_whatever_the_growth() {
        let growing = policy(json!({
            "retryDelaySeconds": 2,
            "useExponentialBackOff": true,
            "backOffMultiplier": 3
        }));
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
        let flat = policy(json!({"retryDelaySeconds": 1, "backOffMultiplier": 3}));
        let previous = Duration::from_secs(1);
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &flat, 0.0)),
            1.0,
            "no back-off, no growth"
        );
        let unit = policy(
            json!({"retryDelaySeconds": 1, "useExponentialBackOff": true, "backOffMultiplier": 1}),
        );
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &unit, 0.0)),
            1.0,
            "a multiplier of one grows nothing"
        );
        let growing = policy(
            json!({"retryDelaySeconds": 1, "useExponentialBackOff": true, "backOffMultiplier": 3}),
        );
        assert_eq!(
            seconds(calculate_redelivery_delay(Some(previous), &growing, 0.0)),
            3.0
        );
    }

    #[test]
    fn the_variance_applies_after_the_growth_and_the_cap_bounds_it() {
        let growing = policy(
            json!({"retryDelaySeconds": 1, "useExponentialBackOff": true, "backOffMultiplier": 3}),
        );
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
        let capped = policy(json!({
            "retryDelaySeconds": 1,
            "useExponentialBackOff": true,
            "backOffMultiplier": 3,
            "maximumRetryDelaySeconds": 5
        }));
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
        let options = policy(json!({
            "retryDelaySeconds": 1,
            "useExponentialBackOff": true,
            "backOffMultiplier": 2
        }));
        let first = calculate_redelivery_delay(None, &options, 0.0);
        let second = calculate_redelivery_delay(Some(first), &options, 0.0);
        let third = calculate_redelivery_delay(Some(second), &options, 0.0);
        assert_eq!(
            [seconds(first), seconds(second), seconds(third)],
            [1.0, 2.0, 4.0]
        );
    }

    #[test]
    fn a_draw_stays_inside_the_factor() {
        let options = policy(json!({
            "useCollisionAvoidance": true,
            "collisionAvoidanceFactor": 0.15
        }));
        for _ in 0..256 {
            let draw = draw_variance(&options);
            assert!(
                (-0.15..=0.15).contains(&draw),
                "the draw {draw} left the factor"
            );
        }
        let plain = policy(json!({"useCollisionAvoidance": false}));
        assert_eq!(draw_variance(&plain), 0.0);
    }
}
