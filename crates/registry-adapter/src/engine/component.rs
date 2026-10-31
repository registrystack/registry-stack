// SPDX-License-Identifier: Apache-2.0

//! The components, ported from Camel's component model
//! (`products/adapter/CONCEPT.md` section 8.8): `direct` for the
//! synchronous in-process call, `http` for the upstream producer,
//! `graphql` for the query-file producer over the same transport, and
//! `rest` for the facade consumer. Every other component, including
//! `log` and `mock` outside the test harness, is not ported.

pub mod direct;
#[cfg(feature = "job-file")]
pub mod file;
pub mod graphql;
pub mod http;
#[cfg(feature = "job-postgres")]
pub mod postgres;
pub mod rest;
