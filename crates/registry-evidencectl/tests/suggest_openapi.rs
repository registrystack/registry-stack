//! Tests for the OpenAPI loading (`openapi.rs`) and schema flattening
//! (`flatten.rs`) stages of `evidencectl source suggest`.
//!
//! `registry-evidencectl` ships only a binary target, so this integration
//! test pulls the modules it needs in directly by path rather than through a
//! library crate. `types` and `openapi`/`flatten` are declared as siblings
//! here, mirroring their nesting under `src/suggest/`, so the `super::types`
//! imports inside `openapi.rs` and `flatten.rs` resolve unchanged.

// `openapi.rs` dispatches a file path or a URL through `fetch`; this binary
// only ever opens files, so the fetching half of that module is unused here.
#[allow(dead_code)]
#[path = "../src/suggest/fetch.rs"]
mod fetch;
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

use types::{OperationKey, ResolvedSchema, SpecSource};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openapi")
        .join(name)
}

/// Opens a fixture through the same entry point the CLI uses, naming it as a
/// local file. Fetching over HTTP is covered in `suggest_fetch.rs`.
fn load(path: &Path) -> anyhow::Result<openapi::Spec> {
    openapi::Spec::open(&SpecSource::File(path.to_path_buf()))
}

fn operation(method: &str, path: &str) -> OperationKey {
    OperationKey {
        method: method.to_string(),
        path: path.to_string(),
    }
}

// --- Spec::open -----------------------------------------------------------

#[test]
fn load_accepts_openapi_3_0_yaml() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    assert!(!spec.operations().is_empty());
}

#[test]
fn load_accepts_openapi_3_1_json() {
    let spec = load(&fixture("records-3.1.json")).expect("loads");
    assert!(!spec.operations().is_empty());
}

#[test]
fn load_rejects_unsupported_openapi_version() {
    let error = load(&fixture("unsupported-version.yaml")).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("3.0") || message.contains("3.1"),
        "message was: {message}"
    );
}

#[test]
fn load_rejects_missing_file() {
    let error = load(&fixture("does-not-exist.yaml")).unwrap_err();
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
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
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
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
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
    let spec = load(&fixture("records-3.1.json")).expect("loads");
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
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");

    let rendered = resolved.schema.0.to_string();
    assert!(
        !rendered.contains("$ref"),
        "refs should be fully inlined: {rendered}"
    );

    // Top-level `nullable: true` string becomes the 3.1 type pair.
    assert_eq!(
        resolved.schema.0["properties"]["recordedOn"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert!(resolved.schema.0["properties"]["recordedOn"]
        .get("nullable")
        .is_none());

    // The $ref'd array item schema (Record) is inlined in place, and its own
    // nested `nullable: true` (notes) is normalized too.
    let record_item = &resolved.schema.0["properties"]["results"]["items"];
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
    let spec = load(&fixture("records-3.1.json")).expect("loads");
    let resolved = spec
        .response_schema(
            &operation("GET", "/records/{id}"),
            "200",
            "application/json",
        )
        .expect("resolves");
    assert_eq!(
        resolved.schema.0["properties"]["status"]["type"],
        serde_json::json!(["string", "null"])
    );
}

#[test]
fn response_schema_rejects_external_ref() {
    let spec = load(&fixture("external-ref.yaml")).expect("loads");
    let error = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("external") || message.contains("remote"),
        "message was: {message}"
    );
}

/// A recursive `$ref` bounds how deep the response can be described, not
/// whether the operation can be drafted from at all. The repeat is cut and
/// named, and everything beside it stays selectable.
#[test]
fn response_schema_cuts_a_ref_cycle_and_notes_it() {
    let spec = load(&fixture("ref-cycle.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    assert!(
        resolved
            .notes
            .iter()
            .any(|note| note.contains("cycle") && note.contains("#/components/schemas/A")),
        "notes were: {:#?}",
        resolved.notes
    );

    let (_, warnings) = flatten::candidate_leaves(&resolved.schema);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("/child/parent")
                && warning.contains("#/components/schemas/A")),
        "warnings were: {warnings:#?}"
    );
}

#[test]
fn a_recursive_schema_still_offers_its_non_recursive_leaves() {
    let spec = load(&fixture("recursive-tree.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/nodes"), "200", "application/json")
        .expect("resolves");
    let (leaves, _) = flatten::candidate_leaves(&resolved.schema);

    // The repeat is cut where it first repeats, so the recursive branch offers
    // nothing and the record's own scalars stay selectable.
    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(pointers, vec!["/id", "/label"]);
}

// --- dialect normalization ---------------------------------------------------

/// A two-member `anyOf`/`oneOf` against `null` is how several generators spell
/// the 3.1 nullable type pair. It states nothing the closed subset cannot
/// already express, so it is rewritten into the pair rather than skipped as an
/// unsupported union.
#[test]
fn a_two_member_union_against_null_becomes_the_nullable_type_pair() {
    let spec = load(&fixture("nullable-unions.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let properties = &resolved.schema.0["properties"];

    assert_eq!(
        properties["note"]["type"],
        serde_json::json!(["string", "null"])
    );
    // The collapsed member's own bounds survive the rewrite.
    assert_eq!(properties["note"]["maxLength"], serde_json::json!(64));
    assert!(properties["note"].get("anyOf").is_none());

    assert_eq!(
        properties["count"]["type"],
        serde_json::json!(["integer", "null"])
    );
    assert_eq!(properties["count"]["maximum"], serde_json::json!(99));
    // A keyword on the union node itself is not lost when the union collapses.
    assert_eq!(
        properties["count"]["description"],
        serde_json::json!("how many were seen")
    );

    // A nullable object keeps its members addressable.
    assert_eq!(
        properties["parent"]["type"],
        serde_json::json!(["object", "null"])
    );
    assert_eq!(
        properties["parent"]["properties"]["id"]["maxLength"],
        serde_json::json!(36)
    );
}

/// The subset admits the pair in one order only, so a document writing it the
/// other way round describes something the subset can express and must not be
/// refused over the spelling.
#[test]
fn a_null_first_type_pair_is_reordered() {
    let spec = load(&fixture("nullable-unions.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    assert_eq!(
        resolved.schema.0["properties"]["reversedPair"]["type"],
        serde_json::json!(["string", "null"])
    );
}

#[test]
fn a_union_of_two_real_types_is_left_for_the_flattener_to_skip() {
    let spec = load(&fixture("nullable-unions.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    assert!(resolved.schema.0["properties"]["either"]
        .get("anyOf")
        .is_some());

    let (leaves, warnings) = flatten::candidate_leaves(&resolved.schema);
    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(
        pointers,
        vec!["/count", "/note", "/parent/id", "/reversedPair"]
    );
    assert!(
        warnings.iter().any(|warning| warning.contains("/either")),
        "warnings were: {warnings:#?}"
    );
}

/// `properties` and `items` are meaningless on anything but an object and an
/// array, so a node carrying one and no `type` is not ambiguous. Reading it is
/// what lets the tool draft from the collection wrappers large registry APIs
/// actually publish; the reading is announced rather than made silently.
#[test]
fn a_structural_keyword_without_a_type_is_read_as_that_type_and_noted() {
    let spec = load(&fixture("implicit-types.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");

    assert_eq!(resolved.schema.0["type"], serde_json::json!("object"));
    assert_eq!(
        resolved.schema.0["properties"]["records"]["type"],
        serde_json::json!("array")
    );
    assert_eq!(
        resolved.schema.0["properties"]["records"]["items"]["type"],
        serde_json::json!("object")
    );
    assert!(
        resolved
            .notes
            .iter()
            .any(|note| note.contains("(root)") && note.contains("object")),
        "notes were: {:#?}",
        resolved.notes
    );
    assert!(
        resolved
            .notes
            .iter()
            .any(|note| note.contains("/records") && note.contains("array")),
        "notes were: {:#?}",
        resolved.notes
    );

    let (leaves, _) = flatten::candidate_leaves(&resolved.schema);
    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(pointers, vec!["/pager/page", "/records/*/id"]);
}

#[test]
fn a_node_with_neither_a_type_nor_a_structural_keyword_stays_untyped() {
    let spec = load(&fixture("implicit-types.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/opaque"), "200", "application/json")
        .expect("resolves");
    assert!(resolved.schema.0["properties"]["anything"]
        .get("type")
        .is_none());

    let (leaves, warnings) = flatten::candidate_leaves(&resolved.schema);
    let pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    assert_eq!(pointers, vec!["/known"]);
    assert!(
        warnings.iter().any(|warning| warning.contains("/anything")),
        "warnings were: {warnings:#?}"
    );
}

#[test]
fn response_schema_rejects_unknown_status() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    let error = spec
        .response_schema(&operation("GET", "/records"), "500", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("500"), "message was: {message}");
}

// --- Spec::servers / Spec::page_size_maximums --------------------------------

#[test]
fn servers_lists_declared_base_urls_in_order() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    assert_eq!(
        spec.servers(),
        vec!["https://records.example.test/api".to_string()]
    );
}

#[test]
fn servers_is_empty_when_undeclared() {
    let spec = load(&fixture("records-3.1.json")).expect("loads");
    assert!(spec.servers().is_empty());
}

#[test]
fn page_size_maximums_reads_matching_query_parameters() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/records"))
        .expect("no ref errors");
    assert_eq!(maximums, vec![100]);
}

#[test]
fn page_size_maximums_is_empty_without_matching_parameters() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("POST", "/records"))
        .expect("no ref errors");
    assert!(maximums.is_empty());
}

#[test]
fn page_size_maximums_matches_limit_named_parameters() {
    let spec = load(&fixture("records-3.1.json")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/records/{id}"))
        .expect("no ref errors");
    assert_eq!(maximums, vec![50]);
}

#[test]
fn page_size_maximums_ignores_a_page_index_beside_a_page_size() {
    let spec = load(&fixture("paging-parameters.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/records"))
        .expect("no ref errors");
    // `page` bounds how many pages exist, not how many items one carries.
    // Reading its maximum as an item count would bound the array at 10000.
    assert_eq!(maximums, vec![50]);
}

#[test]
fn page_size_maximums_reads_every_genuine_size_parameter() {
    let spec = load(&fixture("paging-parameters.yaml")).expect("loads");
    let mut maximums = spec
        .page_size_maximums(&operation("GET", "/events"))
        .expect("no ref errors");
    maximums.sort_unstable();
    assert_eq!(maximums, vec![25, 200]);
}

#[test]
fn page_size_maximums_ignores_names_that_only_contain_a_matching_word() {
    let spec = load(&fixture("paging-parameters.yaml")).expect("loads");
    let maximums = spec
        .page_size_maximums(&operation("GET", "/reports"))
        .expect("no ref errors");
    assert!(
        maximums.is_empty(),
        "a byte ceiling and a rate-limit burst are not page sizes: {maximums:?}"
    );
}

// --- flatten::candidate_leaves ------------------------------------------------

#[test]
fn candidate_leaves_flattens_arrays_and_nullable_records() {
    let spec = load(&fixture("records-3.0.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved.schema);
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
    let spec = load(&fixture("escaping.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved.schema);
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

    let mut pointers: Vec<&str> = leaves.iter().map(|leaf| leaf.pointer.as_str()).collect();
    pointers.sort();
    assert_eq!(pointers, vec!["/tags~1primary", "/tilde~0name"]);
}

#[test]
fn candidate_leaves_skips_and_warns_on_unsupported_constructs() {
    let spec = load(&fixture("unsupported-constructs.yaml")).expect("loads");
    let resolved = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("resolves");
    let (leaves, warnings) = flatten::candidate_leaves(&resolved.schema);

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

/// The sampler refuses an oversized sample before reading it. The loader is
/// held to the same rule, so a mistaken path is named as one rather than read
/// into memory whole.
#[test]
fn an_oversized_document_is_refused_before_it_is_read() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("huge.openapi.yaml");
    let file = std::fs::File::create(&path).expect("create");
    // Sparse where the filesystem supports it: the point is the declared
    // length, not the bytes.
    file.set_len(17 * 1024 * 1024).expect("set_len");
    drop(file);

    let error = load(&path).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("exceeding the"), "message was: {message}");
}
