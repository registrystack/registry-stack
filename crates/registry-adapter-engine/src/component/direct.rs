// SPDX-License-Identifier: Apache-2.0

//! The `direct` component, Camel's synchronous in-process call.
//!
//! `to: direct:<routeId>` runs the target route on the same exchange:
//! body, headers, and properties flow in and come back changed. Errors
//! raised in the target are offered first to the target's own clauses;
//! an unhandled error propagates unchanged to the caller's clauses. The
//! call graph is acyclic and depth bounded, and a `direct:` send is
//! never redelivered: the target's own endpoint sends carry their
//! redelivery.
