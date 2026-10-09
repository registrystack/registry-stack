// SPDX-License-Identifier: Apache-2.0
//! The sealed source of a predecessor package is read through the shared
//! reader, so YAML outside the configuration subset is not a readable baseline.

use super::{retired_access_spellings_read, PackageError};
use serde_json::{json, Value};

#[test]
fn a_predecessor_source_in_the_subset_keeps_its_meaning() {
    let rewritten = retired_access_spellings_read(
        b"accessProfiles:\n- id: staff\n  requiredScopes: []\n  rowBoundaries: []\n",
    )
    .expect("a subset source reads");
    let text = String::from_utf8(rewritten).expect("UTF-8");
    assert!(text.contains("requiredScopes: unrestricted"), "{text}");
    assert!(text.contains("rowBoundaries: unrestricted"), "{text}");
}

#[test]
fn a_predecessor_source_with_an_anchor_and_alias_is_refused() {
    let refused = retired_access_spellings_read(
        b"accessProfiles:\n- id: staff\n  requiredScopes: &scopes []\n- id: other\n  requiredScopes: *scopes\n",
    );
    assert!(
        matches!(refused, Err(PackageError::Derivation)),
        "{refused:?}"
    );
}

#[test]
fn an_empty_predecessor_source_reads_as_null() {
    let rewritten = retired_access_spellings_read(b"# nothing\n").expect("an empty source reads");
    assert_eq!(String::from_utf8(rewritten).expect("UTF-8").trim(), "null");
}

#[test]
fn a_null_that_is_a_value_stays_and_a_null_optional_member_reads_as_absent() {
    let source = json!({
        "label": null,
        "actions": [{
            "id": "retire",
            "description": null,
            "requires": [
                {"input": "asset", "field": "rank", "equals": null, "equalsInput": null}
            ],
            "effects": [{
                "id": "retired",
                "set": {
                    // The adopter named these members after its own fields.
                    "equals": {"fromField": "rank", "fromEffect": null},
                    "schema": {"fromField": "rank", "fromEffect": null}
                }
            }]
        }],
        "entities": [{
            "id": "asset",
            "fields": [{
                "id": "detail",
                "type": "structured",
                "vocabulary": null,
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"note": {"const": null}, "grade": {"enum": [null, 1]}}
                }
            }],
            "hooks": [{
                "id": "rank-cleared",
                "when": {
                    "kind": "fields",
                    "beforeEquals": {"rank": null, "code": "a"},
                    "afterEquals": {"rank": null}
                }
            }],
            "changeRequest": {
                "preconditions": {"requires": [
                    {"field": "rank", "equals": null, "equalsFromRequestField": null}
                ]},
                "evidence": {"requirements": [
                    {"output": "result", "equals": {"grade": null}}
                ]}
            }
        }]
    });
    let rewritten = retired_access_spellings_read(&serde_json::to_vec(&source).expect("JSON"))
        .expect("a subset source reads");
    let read: Value = registry_platform_yaml::Reader::new("rewritten source")
        .scan(&rewritten)
        .expect("the rewritten source stays in the subset")
        .expect("a document")
        .to_json_value();

    assert_eq!(
        read,
        json!({
            "actions": [{
                "id": "retire",
                "requires": [{"input": "asset", "field": "rank", "equals": null}],
                "effects": [{
                    "id": "retired",
                    "set": {
                        "equals": {"fromField": "rank"},
                        "schema": {"fromField": "rank"}
                    }
                }]
            }],
            "entities": [{
                "id": "asset",
                "fields": [{
                    "id": "detail",
                    "type": "structured",
                    "schema": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"note": {"const": null}, "grade": {"enum": [null, 1]}}
                    }
                }],
                "hooks": [{
                    "id": "rank-cleared",
                    "when": {
                        "kind": "fields",
                        "beforeEquals": {"rank": null, "code": "a"},
                        "afterEquals": {"rank": null}
                    }
                }],
                "changeRequest": {
                    "preconditions": {"requires": [{"field": "rank", "equals": null}]},
                    "evidence": {"requirements": [
                        {"output": "result", "equals": {"grade": null}}
                    ]}
                }
            }]
        })
    );
}
