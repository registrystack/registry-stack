// SPDX-License-Identifier: Apache-2.0

//! The `loop` processor, Camel's Loop EIP
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The `expression` form repeats for a count and the `doWhile` form
//! repeats while its predicate holds; `copy` (default false) chooses
//! whether each iteration runs on a copy; `CamelLoopIndex` carries the
//! iteration position. `maximumIterations` is mandatory, and a `doWhile`
//! loop still true at the maximum raises
//! `loop.maximum-iterations-reached`. The several-upstream-pages-per-
//! facade-page pagination shape runs `doWhile` over a property holding
//! the upstream cursor, with an `enrich` per page (section 8.11.7).
