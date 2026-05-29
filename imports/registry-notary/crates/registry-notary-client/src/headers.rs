// SPDX-License-Identifier: Apache-2.0
//! Header and media-type constants for Registry Notary clients.

pub const DATA_PURPOSE: &str = "data-purpose";
pub const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
pub const REQUEST_ID: &str = "x-request-id";
pub const TRACEPARENT: &str = "traceparent";
pub const RETRY_AFTER: &str = "retry-after";
pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_PROBLEM_JSON: &str = "application/problem+json";
pub const APPLICATION_JWT: &str = "application/jwt";
