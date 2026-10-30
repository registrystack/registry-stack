// SPDX-License-Identifier: Apache-2.0

//! The EIP processors, one submodule per ported Enterprise Integration
//! Pattern from the port table (`products/adapter/CONCEPT.md` sections
//! 8.6 and 8.10).
//!
//! Message transformation: `set_body`, `transform`, `set_header`,
//! `set_property`, `remove_header`, `remove_property`, `script`.
//! Routing: `to`, `choice`, `filter`, `stop`, `validate`,
//! `throw_exception`. Splitting and aggregation: `loop`, `split`,
//! `enrich`, and the `aggregation` strategies. Resilience:
//! `circuit_breaker` and `throttle`. Error structure: `do_try`. The
//! `idempotentConsumer` EIP lives beside the idempotency store in
//! `crate::idempotent` (section 9).
//!
//! Camel defaults hold unless the port table says otherwise. Pagination
//! is not an EIP and gets none: the facade side is the continuation
//! contract of section 8.11.2.

pub mod aggregation;
pub mod choice;
pub mod circuit_breaker;
pub mod convert;
pub mod do_try;
pub mod enrich;
pub mod filter;
pub mod r#loop;
pub mod redelivery;
pub mod remove_header;
pub mod remove_property;
pub mod script;
pub mod set_body;
pub mod set_header;
pub mod set_property;
pub mod split;
pub mod stop;
pub mod throttle;
pub mod throw_exception;
pub mod to;
pub mod transform;
pub mod validate;
