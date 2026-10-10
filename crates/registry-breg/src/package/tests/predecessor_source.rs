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

fn read(source: &Value) -> Result<Value, PackageError> {
    let rewritten = retired_access_spellings_read(&serde_json::to_vec(source).expect("JSON"))?;
    Ok(registry_platform_yaml::Reader::new("rewritten source")
        .scan(&rewritten)
        .expect("the rewritten source stays in the subset")
        .expect("a document")
        .to_json_value())
}

/// A project as an earlier release sealed it: each statistical dataset names
/// the profiles that reach it, and its period writes its tag as `kind`.
fn earlier_release_statistical_project() -> Value {
    json!({
        "accessProfiles": [
            {"id": "analyst", "requiredScopes": ["counts"], "permissions": [
                {"entity": "record", "operations": ["list"], "rowBoundaries": [{"field": "region"}]}
            ]},
            {"id": "publisher", "requiredScopes": ["publish"], "permissions": []},
            {"id": "reader", "requiredScopes": ["releases"]},
            {"id": "clerk", "requiredScopes": ["records"], "permissions": []}
        ],
        "statisticalDatasets": [
            {
                "id": "records-by-month",
                "unit": "record",
                "period": {"kind": "flow", "field": "event-date", "granularity": "month", "firstPeriod": "2025-01"},
                "live": ["analyst"],
                "releases": {"publisher": "publisher", "readers": ["reader"]}
            },
            {
                "id": "records-in-force",
                "unit": "record",
                "period": {"kind": "stock", "granularity": "year", "firstPeriod": "2025", "validity": "temporal"},
                "live": ["analyst", "publisher"]
            },
            {
                "id": "records-by-year",
                "unit": "record",
                "period": {"kind": "flow", "field": "event-date", "granularity": "year", "firstPeriod": "2025"},
                "live": ["publisher"],
                "releases": {"publisher": "publisher", "readers": ["publisher", "analyst"]}
            }
        ]
    })
}

#[test]
fn a_predecessor_statistical_dataset_grants_what_its_profile_lists_granted() {
    assert_eq!(
        read(&earlier_release_statistical_project()).expect("the earlier forms read"),
        json!({
            "accessProfiles": [
                {"id": "analyst", "requiredScopes": ["counts"], "permissions": [
                    {"entity": "record", "operations": ["list"], "rowBoundaries": [{"field": "region"}]},
                    // A live profile of a published dataset read its releases.
                    {"dataset": "records-by-month", "operations": ["read-live", "read-releases"]},
                    {"dataset": "records-in-force", "operations": ["read-live"]},
                    {"dataset": "records-by-year", "operations": ["read-releases"]}
                ]},
                {"id": "publisher", "requiredScopes": ["publish"], "permissions": [
                    {"dataset": "records-by-month", "operations": ["publish", "read-releases"]},
                    {"dataset": "records-in-force", "operations": ["read-live"]},
                    // Listing the publisher as a reader gave it nothing more.
                    {"dataset": "records-by-year", "operations": ["read-live", "publish", "read-releases"]}
                ]},
                {"id": "reader", "requiredScopes": ["releases"], "permissions": [
                    {"dataset": "records-by-month", "operations": ["read-releases"]}
                ]},
                // A profile no dataset named gains nothing.
                {"id": "clerk", "requiredScopes": ["records"], "permissions": []}
            ],
            "statisticalDatasets": [
                {
                    "id": "records-by-month",
                    "unit": "record",
                    "period": {"type": "flow", "field": "event-date", "granularity": "month", "firstPeriod": "2025-01"}
                },
                {
                    "id": "records-in-force",
                    "unit": "record",
                    "period": {"type": "stock", "granularity": "year", "firstPeriod": "2025", "validity": "temporal"}
                },
                {
                    "id": "records-by-year",
                    "unit": "record",
                    "period": {"type": "flow", "field": "event-date", "granularity": "year", "firstPeriod": "2025"}
                }
            ]
        })
    );
}

#[test]
fn a_statistical_dataset_in_this_release_s_spelling_reads_as_written() {
    let current = read(&earlier_release_statistical_project()).expect("the earlier forms read");
    assert_eq!(read(&current).expect("the current forms read"), current);
}

#[test]
fn a_predecessor_statistical_dataset_naming_no_declared_profile_is_refused() {
    for (member, value) in [
        ("live", json!(["auditor"])),
        (
            "releases",
            json!({"publisher": "auditor", "readers": ["reader"]}),
        ),
        (
            "releases",
            json!({"publisher": "publisher", "readers": ["auditor"]}),
        ),
        // The lists never held anything but profile ids.
        ("live", json!("analyst")),
        ("releases", json!({"publisher": "publisher"})),
        (
            "releases",
            json!({"publisher": "publisher", "readers": ["reader"], "embargo": "P1D"}),
        ),
    ] {
        let mut source = earlier_release_statistical_project();
        source["statisticalDatasets"][0][member] = value.clone();
        assert!(
            matches!(read(&source), Err(PackageError::Derivation)),
            "{member}: {value}"
        );
    }
}
