// SPDX-License-Identifier: Apache-2.0

//! Aggregation strategies for `split` and `enrich`, compiled in and
//! named after Camel's built-ins (`products/adapter/CONCEPT.md`
//! section 8.6): `useLatest`, `useOriginal`, and `groupedBody`, plus
//! the two JSON-body additions marked as such: `jsonArrayAppend`
//! (`from`, `into`, `uniqueBy`; a duplicate `uniqueBy` value raises
//! `aggregation.duplicate`, so duplicate and shifting pages fail the
//! exchange instead of merging silently) and `jsonMerge` (`from`,
//! `into`).
//!
//! A custom strategy is a `rhai` entrypoint over the old and new bodies,
//! Camel's custom `AggregationStrategy` bean in the port's form:
//! `fn(old, new)` on `split`, with `old` as `()` on the first call, and
//! `fn(original, resource)` on `enrich`, returning
//! `#{ body, properties }` (section 8.11.3).
