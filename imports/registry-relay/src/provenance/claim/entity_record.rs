// SPDX-License-Identifier: Apache-2.0
//! `EntityRecord` v1 credentialSubject builder.
//!
//! The plain entity record response is one flat JSON object, with
//! optional `?expand=` relationship data nested under the relationship
//! name. The credential model splits that view into `{fields, expanded}`
//! so consumers can distinguish projected scalars from related-entity
//! blocks.
//!
//! The split is driven by the relationship name list gathered at the
//! handler. Any key in the plain record whose name matches a requested
//! expansion lands in `expanded`; everything else lands in
//! `fields`. This treats relationship names as a closed set
//! (controlled by the projection config), which means unrelated keys
//! cannot accidentally land in `expanded` and consumers cannot inject
//! unexpected "expanded" content via crafted requests.

use serde_json::{Map, Value};

/// Inputs gathered by the `/{entity}/{id}` handler.
#[derive(Debug, Clone)]
pub struct EntityRecordInput {
    pub subject_uri: String,
    pub dataset: String,
    pub entity: String,
    pub subject_id: String,
    pub record: Value,
    pub expansions: Vec<String>,
    pub as_of_rfc3339: String,
}

/// Build the `credentialSubject` JSON for an `EntityRecord` VC.
#[must_use]
pub fn entity_record_subject(input: &EntityRecordInput) -> Value {
    let (fields, expanded) = split_record(&input.record, &input.expansions);
    let mut subject = Map::new();
    subject.insert("id".to_string(), Value::String(input.subject_uri.clone()));
    subject.insert("dataset".to_string(), Value::String(input.dataset.clone()));
    subject.insert("entity".to_string(), Value::String(input.entity.clone()));
    subject.insert(
        "subjectId".to_string(),
        Value::String(input.subject_id.clone()),
    );
    subject.insert("fields".to_string(), Value::Object(fields));
    if let Some(expanded) = expanded {
        subject.insert("expanded".to_string(), Value::Object(expanded));
    }
    subject.insert(
        "asOf".to_string(),
        Value::String(input.as_of_rfc3339.clone()),
    );
    Value::Object(subject)
}

/// Split the plain record into (fields, expanded). Returns `None` for
/// `expanded` when no expansion key resolves; the caller drops the
/// member from the credential subject when that happens, matching the
/// spec note "`expanded` is omitted entirely when the request did not
/// include `?expand=`".
fn split_record(
    record: &Value,
    expansions: &[String],
) -> (Map<String, Value>, Option<Map<String, Value>>) {
    let mut fields = Map::new();
    let mut expanded = Map::new();
    if let Some(object) = record.as_object() {
        for (key, value) in object {
            if expansions.iter().any(|name| name == key) {
                expanded.insert(key.clone(), value.clone());
            } else {
                fields.insert(key.clone(), value.clone());
            }
        }
    }
    if expansions.is_empty() || expanded.is_empty() {
        (fields, None)
    } else {
        (fields, Some(expanded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn split_with_no_expansions_drops_expanded() {
        let (fields, expanded) = split_record(&json!({"name": "Alice", "age": 30}), &[]);
        assert_eq!(fields.get("name").unwrap(), &json!("Alice"));
        assert!(expanded.is_none());
    }

    #[test]
    fn split_moves_expansion_keys_into_expanded() {
        let record = json!({
            "name": "Alice",
            "household": {"id": "H-1", "members": 3}
        });
        let (fields, expanded) = split_record(&record, &["household".to_string()]);
        assert!(!fields.contains_key("household"));
        let expanded = expanded.expect("expanded present");
        assert_eq!(
            expanded.get("household").unwrap(),
            &json!({"id": "H-1", "members": 3})
        );
    }

    #[test]
    fn split_with_unrelated_expansion_returns_none() {
        // Caller asked for an expansion but the record carries none
        // by that name; expanded must remain absent.
        let (fields, expanded) =
            split_record(&json!({"name": "Alice"}), &["household".to_string()]);
        assert_eq!(fields.get("name").unwrap(), &json!("Alice"));
        assert!(expanded.is_none());
    }

    #[test]
    fn build_subject_omits_expanded_when_absent() {
        let input = EntityRecordInput {
            subject_uri: "https://gw/datasets/ds/entity/X".to_string(),
            dataset: "ds".to_string(),
            entity: "entity".to_string(),
            subject_id: "X".to_string(),
            record: json!({"name": "Alice"}),
            expansions: vec![],
            as_of_rfc3339: "2026-05-16T12:00:00Z".to_string(),
        };
        let subject = entity_record_subject(&input);
        let object = subject.as_object().unwrap();
        assert!(object.get("expanded").is_none());
        assert_eq!(object.get("fields").unwrap(), &json!({"name": "Alice"}));
    }

    #[test]
    fn build_subject_carries_expanded_when_present() {
        let input = EntityRecordInput {
            subject_uri: "https://gw/datasets/ds/entity/X".to_string(),
            dataset: "ds".to_string(),
            entity: "entity".to_string(),
            subject_id: "X".to_string(),
            record: json!({"name": "Alice", "household": {"id": "H-1"}}),
            expansions: vec!["household".to_string()],
            as_of_rfc3339: "2026-05-16T12:00:00Z".to_string(),
        };
        let subject = entity_record_subject(&input);
        let object = subject.as_object().unwrap();
        assert_eq!(
            object.get("expanded").unwrap(),
            &json!({"household": {"id": "H-1"}})
        );
        assert_eq!(object.get("fields").unwrap(), &json!({"name": "Alice"}));
    }
}
