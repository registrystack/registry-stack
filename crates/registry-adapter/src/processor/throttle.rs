// SPDX-License-Identifier: Apache-2.0

//! The `throttle` processor, Camel 4's Throttler
//! (`products/adapter/CONCEPT.md` section 8.6): `mode` (`TotalRequests`
//! default, or `ConcurrentRequests`), a limit expression,
//! `timePeriodMilliseconds` (default 1000), and `rejectExecution`
//! (default false).
//!
//! Divergence: a waiting exchange waits at most until its deadline, then
//! raises `throttle.rejected`, instead of waiting without bound.
