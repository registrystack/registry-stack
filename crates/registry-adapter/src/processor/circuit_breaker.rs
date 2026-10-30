// SPDX-License-Identifier: Apache-2.0

//! The `circuitBreaker` processor: resilience4j semantics and defaults,
//! per EIP node with process-local state, as in Camel
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.7).
//!
//! Defaults: `failureRateThreshold` 50, a count-based sliding window of
//! `slidingWindowCalls` 100, `minimumNumberOfCalls` 100,
//! `openStateWaitSeconds` 60, `maximumHalfOpenCalls` 10,
//! `automaticTransitionFromOpenToHalfOpenEnabled` false,
//! `slowCallRateThreshold` 100, `slowCallDurationThresholdSeconds` 60.
//! A rejected call always raises `breaker.open`, diverging from Camel's
//! `throwExceptionWhenHalfOpenOrOpenState: false` default, and
//! `onFallback` runs on failure and on rejection with its output
//! validated like any route output.
