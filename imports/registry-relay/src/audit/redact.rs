// SPDX-License-Identifier: Apache-2.0
//! Reusable audit query redaction primitives.
//!
//! Sensitive field values are replaced with deterministic, field-bound
//! hashes from `registry-platform-audit` so subject-keyed audit lookup
//! can match future requests without storing raw PII.

use std::collections::BTreeSet;

use registry_platform_audit::{redact as platform_redact, AuditKeyHasher};
use serde_json::Value;

pub use registry_platform_audit::redact::QueryRedactionError;
pub use registry_platform_audit::AuditHashSecret;

/// Redacts URL query parameters into the audit `query_params` shape.
///
/// This wrapper preserves the relay's historical behavior of hashing
/// sensitive lookup values by default. The hashing primitive and
/// secret validation are owned by `registry-platform-audit`.
#[derive(Debug, Clone)]
pub struct QueryRedactor {
    sensitive_fields: BTreeSet<String>,
    hasher: AuditKeyHasher,
}

impl Default for QueryRedactor {
    fn default() -> Self {
        Self {
            sensitive_fields: BTreeSet::new(),
            hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }
}

impl QueryRedactor {
    #[must_use]
    pub fn new<I, S>(sensitive_fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sensitive_fields: normalize_sensitive_fields(sensitive_fields),
            hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn with_hasher<I, S>(hasher: AuditKeyHasher, sensitive_fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sensitive_fields: normalize_sensitive_fields(sensitive_fields),
            hasher,
        }
    }

    #[must_use]
    pub fn redact_query(&self, query: &str) -> Value {
        self.try_redact_query(query).unwrap_or_else(|error| {
            serde_json::json!({
                "_error": {
                    "code": "invalid_query_encoding",
                    "detail": error.to_string(),
                }
            })
        })
    }

    pub fn try_redact_query(&self, query: &str) -> Result<Value, QueryRedactionError> {
        platform_redact::QueryRedactor::with_hasher(
            self.hasher.clone(),
            self.sensitive_fields.iter().cloned(),
        )
        .try_redact_query(query)
    }
}

fn normalize_sensitive_fields<I, S>(sensitive_fields: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    sensitive_fields
        .into_iter()
        .map(|field| field.into().to_ascii_lowercase())
        .collect()
}

/// Unkeyed domain-separated SHA-256. Stable across processes; no
/// brute-force resistance. Kept as an explicit dev/test wrapper around
/// the platform hasher.
#[must_use]
pub fn sensitive_value_hash(field: &str, value: &str) -> String {
    sensitive_value_hash_keyed(&AuditKeyHasher::unkeyed_dev_only(), field, value)
}

/// Hash a field-bound sensitive value through the platform audit hasher.
#[must_use]
pub fn sensitive_value_hash_keyed(hasher: &AuditKeyHasher, field: &str, value: &str) -> String {
    hasher.sensitive_value_hash(field, value)
}

#[must_use]
pub fn redact_query_with_sensitive_fields<I, S>(query: &str, sensitive_fields: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    QueryRedactor::new(sensitive_fields).redact_query(query)
}

#[must_use]
pub fn redact_query_with_secret_and_fields<I, S>(
    hasher: AuditKeyHasher,
    query: &str,
    sensitive_fields: I,
) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    QueryRedactor::with_hasher(hasher, sensitive_fields).redact_query(query)
}

#[cfg(test)]
pub(crate) fn is_secret_param_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "token" | "key" | "api_key" | "apikey" | "password" | "secret" | "authorization" | "auth"
    )
}
