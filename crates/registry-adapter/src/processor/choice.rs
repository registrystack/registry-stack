// SPDX-License-Identifier: Apache-2.0

//! The `choice` processor, Camel's Content-Based Router
//! (`products/adapter/CONCEPT.md` section 8.6): the first matching
//! `when` predicate wins, and `otherwise` runs when none matches.
//!
//! A predicate is an expression whose result is a boolean; a non-boolean
//! result is an error, never a truthiness guess (section 8.5).
