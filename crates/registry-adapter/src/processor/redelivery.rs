// SPDX-License-Identifier: Apache-2.0

//! The redelivery delay of `RedeliveryPolicy` at the pinned tag
//! (`products/adapter/CONCEPT.md` section 8.7,
//! `RedeliveryPolicy.calculateRedeliveryDelay`): the first delay is
//! `retryDelaySeconds`, each later one the previous delay (times the
//! multiplier when backing off), then the collision variance, then the
//! `maximumRetryDelaySeconds` cap, so the cap bounds the varied delay.
//! The computation itself lives in `registry-platform-resilience`; what
//! stays here is the mapping from the model's policy onto it and the
//! collision-avoidance draw.

use std::time::Duration;

use registry_adapter_core::RedeliveryOptions;
use registry_platform_resilience::redelivery::{self, RedeliveryDelayOptions};

/// The delay before the next redelivery, from the delay before the
/// previous one (`None` on the first). `variance` is the
/// collision-avoidance draw, a fraction of the delay plus or minus
/// ([`draw_variance`]); zero when the policy does not ask for it.
pub(crate) fn calculate_redelivery_delay(
    previous: Option<Duration>,
    policy: &RedeliveryOptions,
    variance: f64,
) -> Duration {
    redelivery::calculate_redelivery_delay(
        previous,
        &RedeliveryDelayOptions {
            retry_delay: Duration::from_secs(u64::from(policy.retry_delay_seconds.get())),
            maximum_retry_delay: Duration::from_secs(u64::from(
                policy.maximum_retry_delay_seconds.get(),
            )),
            use_exponential_back_off: policy.use_exponential_back_off,
            back_off_multiplier: policy.back_off_multiplier,
        },
        variance,
    )
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
    fn the_model_policy_maps_onto_the_platform_computation() {
        // The whole order, through the model's own field shapes: the
        // first delay is the retry delay whatever the growth, a later one
        // grows with back-off and a multiplier above one, then variance,
        // then the cap. The computation's own tests live in
        // `registry-platform-resilience`.
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
            seconds(calculate_redelivery_delay(
                Some(Duration::from_secs(2)),
                &growing,
                0.0
            )),
            6.0,
            "the previous delay grows by the multiplier"
        );
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
