//! Narrowing stage: an OpenAPI response schema restricted to a projection
//! selection and rewritten into the closed Version 1 response subset.
//!
//! The inputs are built here as JSON literals rather than loaded through the
//! OpenAPI stage, so a failure names a narrowing rule and never a loader bug.
//! Every expectation is checked against the shipped shapes under
//! `products/evidence/fixtures/source-shapes/*/schemas/response.schema.yaml`:
//! closed objects, `required` as the spec-guaranteed subset of kept members,
//! bounded arrays and strings, and the `[T, "null"]` response pair.

#[allow(dead_code)]
#[path = "../src/suggest/types.rs"]
mod types;

#[allow(dead_code)]
#[path = "../src/suggest/narrow.rs"]
mod narrow;

use std::collections::BTreeMap;

use serde_json::{json, Value};

use narrow::{AdvisoryKind, Plan, Resolution};
use types::{
    BoundKind, BoundValues, NarrowOutcome, Observations, Observed, Provenance, ResolvedSchema,
    SuggestedBound,
};

/// Builds a resolved schema from a JSON literal.
fn schema(value: Value) -> ResolvedSchema {
    ResolvedSchema(value)
}

/// Builds a selection from string literals.
fn selection(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

/// Builds observations for one pointer.
fn observed(pointer: &str, observation: Observed) -> Observations {
    let mut observations = Observations::default();
    observations
        .by_pointer
        .insert(pointer.to_owned(), observation);
    observations
}

/// Builds a one-entry resolution list for the slice entry point, which takes
/// the same pairs as the `BTreeMap` form declared in `types.rs`.
fn resolved(pointer: &str, kind: BoundKind, values: BoundValues) -> Vec<Resolution> {
    vec![((pointer.to_owned(), kind), values)]
}

fn plan(
    schema: &ResolvedSchema,
    entries: &[&str],
    observations: &Observations,
) -> Vec<types::BoundNeed> {
    plan_advisories(schema, entries, observations).needs
}

fn plan_advisories(schema: &ResolvedSchema, entries: &[&str], observations: &Observations) -> Plan {
    narrow::plan_advisories(schema, &selection(entries), observations).expect("plan")
}

fn apply(schema: &ResolvedSchema, entries: &[&str], resolutions: &[Resolution]) -> NarrowOutcome {
    narrow::apply_entries(schema, &selection(entries), resolutions).expect("apply")
}

/// A root object wrapping one property, the smallest schema the subset admits.
fn root(properties: Value, required: Value) -> ResolvedSchema {
    schema(json!({
        "type": "object",
        "required": required,
        "properties": properties,
    }))
}

#[test]
fn an_integer_with_only_a_minimum_raises_a_bound_need() {
    let input = root(
        json!({"total": {"type": "integer", "minimum": 0}}),
        json!(["total"]),
    );

    let needs = plan(&input, &["/total"], &Observations::default());

    assert_eq!(needs.len(), 1, "one unmet bound: {needs:?}");
    assert_eq!(needs[0].pointer, "/total");
    assert_eq!(needs[0].kind, BoundKind::IntegerRange);
    assert!(
        needs[0].suggestion.is_none(),
        "nothing to derive a maximum from: {:?}",
        needs[0].suggestion
    );
}

#[test]
fn an_integer_with_an_enum_needs_no_bound_and_keeps_the_enum() {
    let input = root(
        json!({"total": {"type": "integer", "enum": [0, 1, 2]}}),
        json!(["total"]),
    );

    assert!(plan(&input, &["/total"], &Observations::default()).is_empty());

    let outcome = apply(&input, &["/total"], &[]);
    assert_eq!(
        outcome.schema["properties"]["total"],
        json!({"type": "integer", "enum": [0, 1, 2]})
    );
    assert!(outcome.unresolved.is_empty());
}

#[test]
fn an_integer_with_a_const_needs_no_bound() {
    let input = root(
        json!({"page": {"type": "integer", "const": 1}}),
        json!(["page"]),
    );

    assert!(plan(&input, &["/page"], &Observations::default()).is_empty());
    let outcome = apply(&input, &["/page"], &[]);
    assert_eq!(
        outcome.schema["properties"]["page"],
        json!({"type": "integer", "const": 1})
    );
}

#[test]
fn a_sample_widens_an_integer_range_outward_to_round_numbers() {
    let input = root(json!({"total": {"type": "integer"}}), json!(["total"]));
    let observations = observed(
        "/total",
        Observed {
            min_integer: Some(0),
            max_integer: Some(2),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/total"], &observations);

    let suggestion = needs[0].suggestion.clone().expect("a sample suggestion");
    assert_eq!(
        suggestion,
        SuggestedBound {
            values: BoundValues::IntegerRange {
                minimum: 0,
                maximum: 10
            },
            provenance: Provenance::Sample,
        }
    );
}

/// A sampled integer is usually a counter, and a counter's ceiling is the one
/// bound a single response says least about: the widening is deliberately
/// generous rather than snug around what was seen.
#[test]
fn a_sample_integer_maximum_widens_to_a_generous_power_of_ten() {
    let input = root(json!({"total": {"type": "integer"}}), json!(["total"]));
    let observations = observed(
        "/total",
        Observed {
            min_integer: Some(4),
            max_integer: Some(1_000),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/total"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion").values,
        BoundValues::IntegerRange {
            minimum: 0,
            maximum: 10_000
        },
        "the observed floor of 4 is kept at 0 and 1000 widens past 2000 to 10000"
    );
}

#[test]
fn a_small_sampled_counter_still_gets_a_generous_ceiling() {
    for (observed_maximum, expected) in [(12_i64, 100_i64), (60, 1_000), (2, 10)] {
        let input = root(json!({"total": {"type": "integer"}}), json!(["total"]));
        let observations = observed(
            "/total",
            Observed {
                min_integer: Some(0),
                max_integer: Some(observed_maximum),
                ..Observed::default()
            },
        );

        let needs = plan(&input, &["/total"], &observations);

        assert_eq!(
            needs[0].suggestion.clone().expect("suggestion").values,
            BoundValues::IntegerRange {
                minimum: 0,
                maximum: expected
            },
            "observing {observed_maximum} should suggest a ceiling of {expected}"
        );
    }
}

#[test]
fn a_negative_sample_integer_widens_below_zero() {
    let input = root(json!({"offset": {"type": "integer"}}), json!(["offset"]));
    let observations = observed(
        "/offset",
        Observed {
            min_integer: Some(-30),
            max_integer: Some(5),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/offset"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion").values,
        BoundValues::IntegerRange {
            minimum: -50,
            maximum: 10
        }
    );
}

#[test]
fn a_spec_minimum_survives_into_a_sample_suggestion() {
    let input = root(
        json!({"total": {"type": "integer", "minimum": 1}}),
        json!(["total"]),
    );
    let observations = observed(
        "/total",
        Observed {
            min_integer: Some(3),
            max_integer: Some(3),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/total"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion").values,
        BoundValues::IntegerRange {
            minimum: 1,
            maximum: 10
        },
        "the stated minimum is authoritative; only the missing maximum is derived"
    );
}

#[test]
fn a_string_with_the_date_format_is_kept_and_needs_no_bound() {
    let input = root(
        json!({"recordedOn": {"type": "string", "format": "date"}}),
        json!([]),
    );

    assert!(plan(&input, &["/recordedOn"], &Observations::default()).is_empty());

    let outcome = apply(&input, &["/recordedOn"], &[]);
    assert_eq!(
        outcome.schema["properties"]["recordedOn"],
        json!({"type": "string", "format": "date"})
    );
}

#[test]
fn a_string_with_the_uuid_format_is_suggested_fixed_length_and_loses_the_format() {
    let input = root(
        json!({"trackingId": {"type": "string", "format": "uuid"}}),
        json!(["trackingId"]),
    );

    let plan = plan_advisories(&input, &["/trackingId"], &Observations::default());

    assert_eq!(plan.needs.len(), 1);
    assert_eq!(plan.needs[0].kind, BoundKind::StringLength);
    assert_eq!(
        plan.needs[0].suggestion.clone().expect("suggestion"),
        SuggestedBound {
            values: BoundValues::StringLength {
                min_length: 36,
                max_length: 36
            },
            provenance: Provenance::Format,
        }
    );
    assert!(
        plan.advisories
            .iter()
            .any(|advisory| advisory.pointer == "/trackingId"
                && advisory.kind == AdvisoryKind::DroppedFormat("uuid".to_owned())),
        "the dropped format is reported: {:?}",
        plan.advisories
    );

    let outcome = apply(
        &input,
        &["/trackingId"],
        &resolved(
            "/trackingId",
            BoundKind::StringLength,
            BoundValues::StringLength {
                min_length: 36,
                max_length: 36,
            },
        ),
    );
    assert_eq!(
        outcome.schema["properties"]["trackingId"],
        json!({"type": "string", "minLength": 36, "maxLength": 36}),
        "the closed subset admits only the date formats, so `uuid` is dropped"
    );
}

#[test]
fn a_string_with_an_unsupported_format_suggests_nothing_and_reports_the_drop() {
    let input = root(
        json!({"contact": {"type": "string", "format": "email"}}),
        json!(["contact"]),
    );

    let plan = plan_advisories(&input, &["/contact"], &Observations::default());

    assert_eq!(plan.needs.len(), 1);
    assert!(
        plan.needs[0].suggestion.is_none(),
        "nothing mechanical follows from `email`"
    );
    assert_eq!(
        plan.advisories[0].kind,
        AdvisoryKind::DroppedFormat("email".to_owned())
    );
}

#[test]
fn a_sample_string_length_rounds_up_to_the_next_power_of_two() {
    let input = root(json!({"status": {"type": "string"}}), json!(["status"]));
    let observations = observed(
        "/status",
        Observed {
            max_string_bytes: Some(36),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/status"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion"),
        SuggestedBound {
            values: BoundValues::StringLength {
                min_length: 0,
                max_length: 64
            },
            provenance: Provenance::Sample,
        }
    );
}

#[test]
fn a_short_sample_string_still_gets_the_sixteen_byte_floor() {
    let input = root(json!({"status": {"type": "string"}}), json!(["status"]));
    let observations = observed(
        "/status",
        Observed {
            max_string_bytes: Some(3),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/status"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion").values,
        BoundValues::StringLength {
            min_length: 0,
            max_length: 16
        }
    );
}

#[test]
fn a_string_enum_needs_no_bound_and_is_carried_through() {
    let input = root(
        json!({"status": {"type": "string", "enum": ["open", "closed"]}}),
        json!(["status"]),
    );

    assert!(plan(&input, &["/status"], &Observations::default()).is_empty());

    let outcome = apply(&input, &["/status"], &[]);
    assert_eq!(
        outcome.schema["properties"]["status"],
        json!({"type": "string", "enum": ["open", "closed"]})
    );
}

#[test]
fn an_array_without_max_items_takes_a_widened_clamped_sample_suggestion() {
    let input = root(
        json!({"records": {"type": "array", "items": {"type": "string", "maxLength": 32}}}),
        json!(["records"]),
    );
    let observations = observed(
        "/records",
        Observed {
            max_array_items: Some(2),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/records/*"], &observations);

    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].pointer, "/records");
    assert_eq!(needs[0].kind, BoundKind::ArrayMaxItems);
    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion"),
        SuggestedBound {
            values: BoundValues::MaxItems(8),
            provenance: Provenance::Sample,
        },
        "two observed elements round up to the next multiple of eight"
    );
}

#[test]
fn a_large_sample_array_is_clamped_to_the_subset_ceiling() {
    let input = root(
        json!({"records": {"type": "array", "items": {"type": "string", "maxLength": 32}}}),
        json!(["records"]),
    );
    let observations = observed(
        "/records",
        Observed {
            max_array_items: Some(500),
            ..Observed::default()
        },
    );

    let needs = plan(&input, &["/records/*"], &observations);

    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion").values,
        BoundValues::MaxItems(256),
        "the closed subset admits maxItems 1..=256"
    );
}

#[test]
fn a_spec_max_items_outside_the_subset_is_clamped_and_credited_to_the_ceiling() {
    let input = root(
        json!({
            "records": {
                "type": "array",
                "maxItems": 5_000,
                "items": {"type": "string", "maxLength": 32}
            }
        }),
        json!(["records"]),
    );

    let needs = plan(&input, &["/records/*"], &Observations::default());

    assert_eq!(needs.len(), 1);
    assert_eq!(
        needs[0].suggestion.clone().expect("suggestion"),
        SuggestedBound {
            values: BoundValues::MaxItems(256),
            provenance: Provenance::SubsetCeiling,
        },
        "5000 is not the number the draft ends up stating, so the document does not \
         get the credit for the 256 that replaces it"
    );

    let outcome = apply(&input, &["/records/*"], &[]);
    assert!(
        outcome.schema["properties"]["records"]
            .get("maxItems")
            .is_none(),
        "an out-of-subset spec bound is never emitted unresolved"
    );
}

#[test]
fn a_spec_max_items_inside_the_subset_raises_no_need() {
    let input = root(
        json!({
            "records": {
                "type": "array",
                "maxItems": 2,
                "items": {"type": "string", "maxLength": 32}
            }
        }),
        json!(["records"]),
    );

    assert!(plan(&input, &["/records/*"], &Observations::default()).is_empty());

    let outcome = apply(&input, &["/records/*"], &[]);
    assert_eq!(
        outcome.schema["properties"]["records"],
        json!({
            "type": "array",
            "minItems": 0,
            "maxItems": 2,
            "items": {"type": "string", "maxLength": 32}
        })
    );
}

#[test]
fn a_record_under_a_wildcard_requires_only_the_kept_members_the_spec_guarantees() {
    let input = root(
        json!({
            "total": {"type": "integer", "minimum": 0, "maximum": 1000000},
            "results": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "required": ["id", "status"],
                    "properties": {
                        "id": {"type": "string", "maxLength": 64},
                        "status": {"type": "string", "enum": ["open", "closed"]},
                        "note": {"type": "string", "maxLength": 8}
                    }
                }
            }
        }),
        json!(["total", "results"]),
    );

    let outcome = apply(&input, &["/total", "/results/*/id"], &[]);

    assert_eq!(
        outcome.schema,
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["results", "total"],
            "properties": {
                "total": {"type": "integer", "minimum": 0, "maximum": 1000000},
                "results": {
                    "type": "array",
                    "minItems": 0,
                    "maxItems": 2,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string", "maxLength": 64}
                        }
                    }
                }
            }
        }),
        "unselected members leave, and `status` leaves `required` with them"
    );
    assert!(outcome.unresolved.is_empty());
}

#[test]
fn a_record_the_spec_does_not_guarantee_gets_an_empty_required_list() {
    let input = root(
        json!({
            "results": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "properties": {"recordedOn": {"type": "string", "format": "date"}}
                }
            }
        }),
        json!(["results"]),
    );

    let outcome = apply(&input, &["/results/*/recordedOn"], &[]);

    assert_eq!(
        outcome.schema["properties"]["results"]["items"]["required"],
        json!([]),
        "projection drops a leaf the record did not carry, so nothing is required"
    );
}

#[test]
fn a_nullable_type_pair_is_preserved_through_narrowing() {
    let input = root(
        json!({
            "result": {
                "type": ["object", "null"],
                "properties": {
                    "code": {"type": ["string", "null"], "maxLength": 32}
                }
            }
        }),
        json!([]),
    );

    let outcome = apply(&input, &["/result/code"], &[]);

    assert_eq!(
        outcome.schema["properties"]["result"],
        json!({
            "type": ["object", "null"],
            "additionalProperties": false,
            "required": [],
            "properties": {"code": {"type": ["string", "null"], "maxLength": 32}}
        })
    );
}

#[test]
fn an_explicit_null_the_spec_does_not_admit_is_reported_as_an_advisory() {
    let input = root(
        json!({"status": {"type": "string", "maxLength": 32}}),
        json!(["status"]),
    );
    let observations = observed(
        "/status",
        Observed {
            saw_null: true,
            max_string_bytes: Some(4),
            ..Observed::default()
        },
    );

    let plan = plan_advisories(&input, &["/status"], &observations);

    assert!(plan.needs.is_empty(), "the spec already bounds the string");
    assert_eq!(plan.advisories.len(), 1);
    assert_eq!(plan.advisories[0].pointer, "/status");
    assert_eq!(plan.advisories[0].kind, AdvisoryKind::NullOutsideSpec);
    assert!(
        plan.advisories[0].message().contains("null"),
        "the advisory explains itself: {}",
        plan.advisories[0].message()
    );
}

#[test]
fn a_nullable_leaf_that_saw_null_raises_no_advisory() {
    let input = root(
        json!({"status": {"type": ["string", "null"], "maxLength": 32}}),
        json!(["status"]),
    );
    let observations = observed(
        "/status",
        Observed {
            saw_null: true,
            ..Observed::default()
        },
    );

    assert!(plan_advisories(&input, &["/status"], &observations)
        .advisories
        .is_empty());
}

#[test]
fn an_ancestor_and_its_descendant_cannot_both_be_selected() {
    let input = root(
        json!({
            "results": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "properties": {"id": {"type": "string", "maxLength": 8}}
                }
            }
        }),
        json!(["results"]),
    );

    let error = narrow::apply_entries(&input, &selection(&["/results", "/results/*/id"]), &[])
        .expect_err("overlapping projection entries are rejected");
    let message = format!("{error:#}");

    assert!(message.contains("/results"), "{message}");
    assert!(message.contains("/results/*/id"), "{message}");
    assert!(message.contains("overlap"), "{message}");
}

#[test]
fn a_duplicate_selection_entry_is_rejected() {
    let input = root(json!({"total": {"type": "integer", "const": 1}}), json!([]));

    let error = narrow::plan_advisories(
        &input,
        &selection(&["/total", "/total"]),
        &Observations::default(),
    )
    .expect_err("duplicate projection entries are rejected");
    let message = format!("{error:#}");

    assert!(message.contains("/total"), "{message}");
    assert!(message.contains("duplicat"), "{message}");
}

#[test]
fn a_numeric_index_into_an_array_is_rejected_in_favour_of_the_wildcard() {
    let input = root(
        json!({
            "results": {
                "type": "array",
                "maxItems": 2,
                "items": {"type": "string", "maxLength": 8}
            }
        }),
        json!([]),
    );

    let error = narrow::apply_entries(&input, &selection(&["/results/0"]), &[])
        .expect_err("numeric indexes are not projection syntax");
    let message = format!("{error:#}");

    assert!(message.contains('*'), "{message}");
}

#[test]
fn a_selection_that_is_not_in_the_schema_is_rejected() {
    let input = root(json!({"total": {"type": "integer", "const": 1}}), json!([]));

    let error = narrow::apply_entries(&input, &selection(&["/missing"]), &[])
        .expect_err("an unknown pointer is a visible failure");

    assert!(format!("{error:#}").contains("/missing"));
}

#[test]
fn an_unresolved_bound_is_omitted_from_the_schema_and_reported() {
    let input = root(
        json!({
            "total": {"type": "integer"},
            "records": {"type": "array", "items": {"type": "string"}}
        }),
        json!(["total"]),
    );

    let outcome = apply(&input, &["/total", "/records/*"], &[]);

    let total = &outcome.schema["properties"]["total"];
    assert_eq!(total, &json!({"type": "integer"}));
    assert!(total.get("minimum").is_none() && total.get("maximum").is_none());
    let records = &outcome.schema["properties"]["records"];
    assert!(records.get("maxItems").is_none());
    assert!(records["items"].get("maxLength").is_none());

    let reported: Vec<(&str, &BoundKind)> = outcome
        .unresolved
        .iter()
        .map(|need| (need.pointer.as_str(), &need.kind))
        .collect();
    assert_eq!(
        reported,
        vec![
            ("/records", &BoundKind::ArrayMaxItems),
            ("/records/*", &BoundKind::StringLength),
            ("/total", &BoundKind::IntegerRange),
        ],
        "unresolved bounds are reported in schema order"
    );
}

#[test]
fn a_resolved_bound_is_written_into_the_schema() {
    let input = root(json!({"total": {"type": "integer"}}), json!(["total"]));

    let outcome = apply(
        &input,
        &["/total"],
        &resolved(
            "/total",
            BoundKind::IntegerRange,
            BoundValues::IntegerRange {
                minimum: 0,
                maximum: 1_000_000,
            },
        ),
    );

    assert_eq!(
        outcome.schema["properties"]["total"],
        json!({"type": "integer", "minimum": 0, "maximum": 1000000})
    );
    assert!(outcome.unresolved.is_empty());
}

#[test]
fn unselected_siblings_are_pruned_from_every_level() {
    let input = root(
        json!({
            "total": {"type": "integer", "minimum": 0, "maximum": 100},
            "secret": {"type": "string", "maxLength": 32},
            "meta": {
                "type": "object",
                "required": ["page"],
                "properties": {
                    "page": {"type": "integer", "const": 1},
                    "cursor": {"type": "string", "maxLength": 64}
                }
            }
        }),
        json!(["total", "secret", "meta"]),
    );

    let outcome = apply(&input, &["/total", "/meta/page"], &[]);

    assert_eq!(
        outcome.schema,
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["meta", "total"],
            "properties": {
                "total": {"type": "integer", "minimum": 0, "maximum": 100},
                "meta": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["page"],
                    "properties": {"page": {"type": "integer", "const": 1}}
                }
            }
        })
    );
}

#[test]
fn selecting_a_container_keeps_its_whole_subtree() {
    let input = root(
        json!({
            "meta": {
                "type": "object",
                "required": ["page"],
                "properties": {
                    "page": {"type": "integer", "const": 1},
                    "cursor": {"type": "string", "maxLength": 64}
                }
            },
            "other": {"type": "string", "maxLength": 4}
        }),
        json!(["meta", "other"]),
    );

    let outcome = apply(&input, &["/meta"], &[]);

    assert_eq!(
        outcome.schema["properties"]["meta"]["properties"]["cursor"],
        json!({"type": "string", "maxLength": 64})
    );
    assert!(outcome.schema["properties"].get("other").is_none());
}

#[test]
fn an_escaped_segment_addresses_the_literal_key() {
    let input = root(
        json!({"a/b": {"type": "string", "maxLength": 8}, "c~d": {"type": "string", "maxLength": 8}}),
        json!([]),
    );

    let outcome = apply(&input, &["/a~1b", "/c~0d"], &[]);

    assert!(outcome.schema["properties"].get("a/b").is_some());
    assert!(outcome.schema["properties"].get("c~d").is_some());
}

#[test]
fn a_type_outside_the_closed_subset_is_rejected() {
    let input = root(json!({"score": {"type": "number"}}), json!(["score"]));

    let error = narrow::apply_entries(&input, &selection(&["/score"]), &[])
        .expect_err("`number` is outside the closed Version 1 subset");

    assert!(format!("{error:#}").contains("number"));
}

#[test]
fn a_resolution_outside_the_subset_range_is_rejected() {
    let input = root(
        json!({"records": {"type": "array", "items": {"type": "string", "maxLength": 8}}}),
        json!([]),
    );

    let error = narrow::apply_entries(
        &input,
        &selection(&["/records/*"]),
        &resolved(
            "/records",
            BoundKind::ArrayMaxItems,
            BoundValues::MaxItems(1_000),
        ),
    )
    .expect_err("a resolved maxItems above 256 is outside the subset");

    assert!(format!("{error:#}").contains("256"));
}

#[test]
fn a_resolution_that_matches_no_need_is_rejected() {
    let input = root(
        json!({"total": {"type": "integer", "minimum": 0, "maximum": 10}}),
        json!(["total"]),
    );

    let error = narrow::apply_entries(
        &input,
        &selection(&["/total"]),
        &resolved(
            "/totl",
            BoundKind::IntegerRange,
            BoundValues::IntegerRange {
                minimum: 0,
                maximum: 10,
            },
        ),
    )
    .expect_err("a stray resolution is a visible failure");

    assert!(format!("{error:#}").contains("/totl"));
}

#[test]
fn an_empty_selection_is_rejected() {
    let input = root(json!({"total": {"type": "integer", "const": 1}}), json!([]));

    assert!(narrow::apply_entries(&input, &[], &[]).is_err());
}

#[test]
fn the_map_entry_point_narrows_the_same_schema() {
    let input = root(
        json!({"total": {"type": "integer", "minimum": 0, "maximum": 10}}),
        json!(["total"]),
    );

    let outcome = narrow::apply(&input, &selection(&["/total"]), &BTreeMap::new())
        .expect("the map entry point delegates to the slice one");

    assert_eq!(
        outcome.schema["properties"]["total"],
        json!({"type": "integer", "minimum": 0, "maximum": 10})
    );
}
