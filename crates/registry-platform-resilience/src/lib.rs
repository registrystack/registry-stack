//! Generic in-process resilience primitives.
//!
//! Two independent primitives live here, both process-local and both
//! carrying no product vocabulary: no exchange, route, or error class.
//! A caller that retries failed calls computes its delays from
//! [`redelivery`], and a caller that guards calls behind a breaker runs
//! its state machine from [`circuit_breaker`]. Neither primitive starts
//! a task, holds a thread, or performs I/O; the breaker advances its
//! phases lazily, on the calls and records its caller makes.

pub mod circuit_breaker;
pub mod redelivery;
