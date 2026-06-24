// SPDX-License-Identifier: Apache-2.0
//! The minimized script context (`ctx`) passed to the entrypoint.
//!
//! A script sees only what it strictly needs to perform a lookup. In
//! particular it never sees a raw credential, claim configuration, requester
//! identity, or any correlation identifier. The single credential-shaped field
//! is `credential_public`: an opaque, caller-provided JSON object that contains
//! only public material (e.g. a client id or public endpoint), never a secret.

use serde_json::{json, Map, Value};

/// The lookup key the script should resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The field name being looked up (e.g. `"nationalId"`).
    pub field: String,
    /// The value to look up.
    pub value: String,
}

/// Builder for the minimized `ctx` object handed to a script.
///
/// Only the whitelisted fields below ever reach the script. Construct with
/// [`ScriptCtx::new`] then add optional fields, and call [`ScriptCtx::build`]
/// to produce the JSON object.
#[derive(Debug, Clone)]
pub struct ScriptCtx {
    source_id: String,
    dataset: String,
    entity: String,
    lookup: Lookup,
    fields: Vec<String>,
    limit: u64,
    purpose: String,
    credential_public: Value,
}

impl ScriptCtx {
    /// Start a context with the required fields. `credential_public` defaults
    /// to an empty object and may be replaced with [`ScriptCtx::credential_public`].
    pub fn new(
        source_id: impl Into<String>,
        dataset: impl Into<String>,
        entity: impl Into<String>,
        lookup: Lookup,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            dataset: dataset.into(),
            entity: entity.into(),
            lookup,
            fields: Vec::new(),
            limit: 0,
            purpose: purpose.into(),
            credential_public: Value::Object(Map::new()),
        }
    }

    /// Set the requested output fields.
    pub fn fields(mut self, fields: Vec<String>) -> Self {
        self.fields = fields;
        self
    }

    /// Set the record limit.
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    /// Set the public (non-secret) credential object.
    ///
    /// The caller is responsible for ensuring this contains no secret material;
    /// the engine treats it as opaque public data.
    pub fn credential_public(mut self, credential_public: Value) -> Self {
        self.credential_public = credential_public;
        self
    }

    /// Build the minimized `ctx` JSON object. The shape is fixed and contains
    /// *only* the whitelisted fields.
    pub fn build(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "dataset": self.dataset,
            "entity": self.entity,
            "lookup": {
                "field": self.lookup.field,
                "value": self.lookup.value,
            },
            "fields": self.fields,
            "limit": self.limit,
            "purpose": self.purpose,
            "credential_public": self.credential_public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_contains_only_whitelisted_keys() {
        let ctx = ScriptCtx::new(
            "dhis2",
            "tei",
            "person",
            Lookup {
                field: "nationalId".into(),
                value: "12345".into(),
            },
            "verify",
        )
        .fields(vec!["firstName".into(), "lastName".into()])
        .limit(5)
        .credential_public(serde_json::json!({ "client_id": "abc" }));

        let v = ctx.build();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "credential_public",
                "dataset",
                "entity",
                "fields",
                "limit",
                "lookup",
                "purpose",
                "source_id",
            ]
        );
        assert_eq!(v["lookup"]["value"], "12345");
        assert_eq!(v["credential_public"]["client_id"], "abc");
        // No secret/correlation/identity fields leak in.
        assert!(obj.get("credential").is_none());
        assert!(obj.get("requester").is_none());
        assert!(obj.get("correlation_id").is_none());
    }
}
