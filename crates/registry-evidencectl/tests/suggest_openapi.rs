//! Tests for the OpenAPI loading (`openapi.rs`) and schema flattening
//! (`flatten.rs`) stages of `evidencectl source suggest`.
//!
//! `registry-evidencectl` ships only a binary target, so this integration
//! test pulls the modules it needs in directly by path rather than through a
//! library crate. `types` and `openapi`/`flatten` are declared as siblings
//! here, mirroring their nesting under `src/suggest/`, so the `super::types`
//! imports inside `openapi.rs` and `flatten.rs` resolve unchanged.

#[path = "../src/suggest/flatten.rs"]
mod flatten;
#[path = "../src/suggest/openapi.rs"]
mod openapi;
// `types.rs` is shared across every pipeline stage; this test binary only
// exercises the openapi/flatten slice of it, so the rest looks unused to
// this crate's own dead-code analysis even though the real `evidencectl`
// binary uses all of it once every stage is wired together.
#[allow(dead_code)]
#[path = "../src/suggest/types.rs"]
mod types;

use std::path::{Path, PathBuf};

use types::{OperationKey, ResolvedSchema};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openapi")
        .join(name)
}

fn operation(method: &str, path: &str) -> OperationKey {
    OperationKey {
        method: method.to_string(),
        path: path.to_string(),
    }
}

// --- Spec::load ------------------------------------------------------------

#[test]
fn load_accepts_openapi_3_0_yaml() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    assert!(!spec.operations().is_empty());
}

#[test]
fn load_accepts_openapi_3_1_json() {
    let spec = openapi::Spec::load(&fixture("records-3.1.json")).expect("loads");
    assert!(!spec.operations().is_empty());
}

#[test]
fn load_rejects_unsupported_openapi_version() {
    let error = openapi::Spec::load(&fixture("unsupported-version.yaml")).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("3.0") || message.contains("3.1"),
        "message was: {message}"
    );
}

#[test]
fn load_rejects_missing_file() {
    let error = openapi::Spec::load(&fixture("does-not-exist.yaml")).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("does-not-exist.yaml"),
        "message was: {message}"
    );
}

// --- Spec::operations --------------------------------------------------------

/// The runtime's fixed-request method is an enumeration of GET and POST, so an
/// operation on any other method is not offerable: the fixture's `DELETE
/// /records` carries a JSON response and is still absent from the listing.
#[test]
fn operations_lists_only_the_methods_the_runtime_admits() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let mut keys: Vec<OperationKey> = spec
        .operations()
        .into_iter()
        .map(|summary| summary.key)
        .collect();
    keys.sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
    assert_eq!(
        keys,
        vec![operation("GET", "/records"), operation("POST", "/records")]
    );
}

#[test]
fn operations_reports_summary_and_json_responses() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let get_records = spec
        .operations()
        .into_iter()
        .find(|summary| summary.key == operation("GET", "/records"))
        .expect("GET /records present");
    assert_eq!(get_records.summary.as_deref(), Some("Search records"));
    assert_eq!(
        get_records.json_responses,
        vec![("200".to_string(), "application/json".to_string())]
    );
}

#[test]
fn operations_collects_every_json_response_status() {
    let spec = openapi::Spec::load(&fixture("records-3.1.json")).expect("loads");
    let get_record = spec
        .operations()
        .into_iter()
        .find(|summary| summary.key == operation("GET", "/records/{id}"))
        .expect("GET /records/{id} present");
    let mut responses = get_record.json_responses;
    responses.sort();
    assert_eq!(
        responses,
        vec![
            ("200".to_string(), "application/json".to_string()),
            ("404".to_string(), "application/json".to_string()),
        ]
    );
}

// --- Spec::response_schema ---------------------------------------------------

#[test]
fn response_schema_inlines_local_refs_and_normalizes_nullable() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");

    let rendered = resolved.0.to_string();
    assert!(
        !rendered.contains("$ref"),
        "refs should be fully inlined: {rendered}"
    );

    // Top-level `nullable: true` string becomes the 3.1 type pair.
    assert_eq!(
        resolved.0["properties"]["recordedOn"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert!(resolved.0["properties"]["recordedOn"]
        .get("nullable")
        .is_none());

    // The $ref'd array item schema (Record) is inlined in place, and its own
    // nested `nullable: true` (notes) is normalized too.
    let record_item = &resolved.0["properties"]["results"]["items"];
    assert_eq!(
        record_item["properties"]["trackingId"]["type"],
        serde_json::json!("string")
    );
    assert_eq!(
        record_item["properties"]["notes"]["type"],
        serde_json::json!(["string", "null"])
    );
}

#[test]
fn response_schema_passes_through_3_1_type_arrays_unchanged() {
    let spec = openapi::Spec::load(&fixture("records-3.1.json")).expect("loads");
    let resolved = spec
        .response_schema(
            &operation("GET", "/records/{id}"),
            "200",
            "application/json",
        )
        .expect("resolves");
    assert_eq!(
        resolved.0["properties"]["status"]["type"],
        serde_json::json!(["string", "null"])
    );
}

#[test]
fn response_schema_rejects_external_ref() {
    let spec = openapi::Spec::load(&fixture("external-ref.yaml")).expect("loads");
    let error = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("external") || message.contains("remote"),
        "message was: {message}"
    );
}

#[test]
fn response_schema_rejects_ref_cycle() {
    let spec = openapi::Spec::load(&fixture("ref-cycle.yaml")).expect("loads");
    let error = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("cycle"), "message was: {message}");
}

#[test]
fn response_schema_rejects_unknown_status() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let error = spec
        .response_schema(&operation("GET", "/records"), "500", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("500"), "message was: {message}");
}

// --- Spec::servers / Spec::page_size_maximums --------------------------------

#[test]
fn servers_lists_declared_base_urls_in_order() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    assert_eq!(
        spec.servers(),
        vec!["https://records.example.test/api".to_string()]
    );
}

#[test]
fn servers_is_empty_when_undeclared() {
    let spec = openapi::Spec::load(&fixture("records-3.1.json")).expect("loads");
    assert!(spec.servers().is_empty());
}

#[test]
fn page_size_maximums_reads_matching_query_parameters() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/records"))
        .expect("no ref errors");
    assert_eq!(maximums, vec![100]);
}

#[test]
fn page_size_maximums_is_empty_without_matching_parameters() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("POST", "/records"))
        .expect("no ref errors");
    assert!(maximums.is_empty());
}

#[test]
fn page_size_maximums_matches_limit_named_parameters() {
    let spec = openapi::Spec::load(&fixture("records-3.1.json")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/records/{id}"))
        .expect("no ref errors");
    assert_eq!(maximums, vec![50]);
}

// --- flatten::candidate_leaves ------------------------------------------------

#[test]
fn candidate_leaves_flattens_arrays_and_nullable_records() {
    let spec = openapi::Spec::load(&fixture("records-3.0.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved);
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(
        pointers,
        vec![
            "/recordedOn",
            "/results/*/notes",
            "/results/*/status",
            "/results/*/trackingId",
            "/total",
        ]
    );

    let recorded_on = leaves
        .iter()
        .find(|leaf| leaf.pointer == "/recordedOn")
        .expect("present");
    assert_eq!(recorded_on.type_label, "string (date-time)");
    assert!(recorded_on.nullable);

    let notes = leaves
        .iter()
        .find(|leaf| leaf.pointer == "/results/*/notes")
        .expect("present");
    assert!(notes.nullable);

    let total = leaves
        .iter()
        .find(|leaf| leaf.pointer == "/total")
        .expect("present");
    assert_eq!(total.type_label, "integer");
    assert!(!total.nullable);
}

#[test]
fn candidate_leaves_escapes_member_names_per_rfc_6901() {
    let spec = openapi::Spec::load(&fixture("escaping.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved);
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(pointers, vec!["/tags~1primary", "/tilde~0name"]);
}

#[test]
fn candidate_leaves_skips_and_warns_on_unsupported_constructs() {
    let spec = openapi::Spec::load(&fixture("unsupported-constructs.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved);

    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(pointers, vec!["/simpleAllOf", "/trackingId"]);

    let simple_all_of = leaves
        .iter()
        .find(|leaf| leaf.pointer == "/simpleAllOf")
        .expect("present");
    assert_eq!(simple_all_of.type_label, "string (date)");

    assert_eq!(warnings.len(), 5, "warnings: {warnings:#?}");
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("/choice") && warning.contains("oneOf")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("/wildcard") && warning.contains("additionalProperties")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("/missingItems") && warning.contains("items")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("/freeform") && warning.contains("properties")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("/multiType")));
}

#[test]
fn candidate_leaves_truncates_at_depth_limit_and_warns() {
    fn nested_object(remaining: usize) -> serde_json::Value {
        if remaining == 0 {
            serde_json::json!({"type": "string"})
        } else {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": { "level": nested_object(remaining - 1) },
            })
        }
    }

    let schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "shallow": {"type": "string"},
            "deep": nested_object(20),
        },
    });
    let resolved = ResolvedSchema(schema);
    let (leaves, warnings) = flatten::candidate_leaves(&resolved);

    let pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    assert_eq!(pointers, vec!["/shallow"]);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("16") && warning.contains("/deep")),
        "warnings: {warnings:#?}"
    );
}
