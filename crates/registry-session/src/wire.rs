// SPDX-License-Identifier: Apache-2.0

//! Names the service and its generated gateway configuration share.
//!
//! The service's answers and the gateway fragments it generates must agree on
//! these values, so both read them from here.

/// The response header that only the session service's own answers carry: the
/// check's denials, the gateway's local reply when the check fails, and the
/// public routes' problem answers. A page reads it to tell the session's own
/// `session.expired` or `session.unavailable` from a product's answer with the
/// same status or code. The gateway removes it from every upstream answer
/// except the service's own public routes.
pub const ANSWER_MARKER_HEADER: &str = "registry-session-answer";

/// The value of [`ANSWER_MARKER_HEADER`].
pub const ANSWER_MARKER_VALUE: &str = "1";
