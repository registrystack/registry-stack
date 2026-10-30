// SPDX-License-Identifier: Apache-2.0

//! The components, ported from Camel's component model
//! (`products/adapter/CONCEPT.md` section 8.8): `direct` for the
//! synchronous in-process call, `http` for the upstream producer, and
//! `rest` for the facade consumer. The `graphql` producer arrives in
//! Increment 3; every other component, including `log` and `mock`
//! outside the test harness, is not ported.

pub mod direct;
pub mod http;
pub mod rest;
