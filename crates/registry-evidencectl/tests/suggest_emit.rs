//! Emit stage: draft artifacts from a narrowed response schema, write them
//! into a deployment project, and classify `evidence check` output.
//!
//! Inputs are built here as `NarrowOutcome`/`EmitInputs` literals rather than
//! produced by the other pipeline stages, so a failure names an emit-stage
//! rule and never a bug in the OpenAPI loader, the sampler, or the narrowing
//! heuristics (all still placeholders as this file is written).

use registry_evidence_authoring::openapi::types;

#[allow(dead_code)]
#[path = "../src/evidence_binary.rs"]
mod evidence_binary;

#[allow(dead_code)]
#[path = "../src/suggest/emit.rs"]
mod emit;

use std::path::{Path, PathBuf};

use serde_json::json;

use emit::{CheckClassification, EmitInputs};
use types::{
    BoundKind, BoundNeed, BoundValues, NarrowOutcome, OperationKey, Provenance, SpecSource,
    SuggestedBound,
};

/// A schema exercising every case the response-schema renderer must handle:
/// a resolved integer bound (derived from the spec), an unresolved array
/// missing `maxItems`, a nested unresolved string missing length bounds
/// (despite carrying a sample-derived suggestion nobody confirmed yet), and a
/// nullable string that needs no bound because `format` alone satisfies the
/// subset.
fn narrow_outcome_fixture() -> NarrowOutcome {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["total"],
        "properties": {
            "total": {"type": "integer", "minimum": 0, "maximum": 1000000},
            "event_date": {"type": ["string", "null"], "format": "date"},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [],
                    "properties": {
                        "status": {"type": "string"}
                    }
                }
            }
        }
    });

    let unresolved = vec![
        BoundNeed {
            pointer: "/results".to_owned(),
            kind: BoundKind::ArrayMaxItems,
            suggestion: None,
        },
        BoundNeed {
            pointer: "/results/*/status".to_owned(),
            kind: BoundKind::StringLength,
            suggestion: Some(SuggestedBound {
                values: BoundValues::StringLength {
                    min_length: 0,
                    max_length: 64,
                },
                provenance: Provenance::Sample,
            }),
        },
    ];

    NarrowOutcome { schema, unresolved }
}

fn needs_fixture() -> Vec<BoundNeed> {
    vec![
        BoundNeed {
            pointer: "/total".to_owned(),
            kind: BoundKind::IntegerRange,
            suggestion: Some(SuggestedBound {
                values: BoundValues::IntegerRange {
                    minimum: 0,
                    maximum: 1_000_000,
                },
                provenance: Provenance::Spec,
            }),
        },
        BoundNeed {
            pointer: "/results".to_owned(),
            kind: BoundKind::ArrayMaxItems,
            suggestion: None,
        },
        BoundNeed {
            pointer: "/results/*/status".to_owned(),
            kind: BoundKind::StringLength,
            suggestion: Some(SuggestedBound {
                values: BoundValues::StringLength {
                    min_length: 0,
                    max_length: 64,
                },
                provenance: Provenance::Sample,
            }),
        },
    ]
}

fn base_inputs() -> EmitInputs {
    EmitInputs {
        source_id: "search-a".to_owned(),
        operation: OperationKey {
            method: "GET".to_owned(),
            path: "/v1/records".to_owned(),
        },
        status: "200".to_owned(),
        media_type: "application/json".to_owned(),
        base_url_suggestion: emit::split_server_url("https://api.example.invalid"),
        base_url: None,
        selection: vec![
            "/total".to_owned(),
            "/event_date".to_owned(),
            "/results/*/status".to_owned(),
        ],
        narrowed: narrow_outcome_fixture(),
        needs: needs_fixture(),
        openapi: SpecSource::File(PathBuf::from("tests/fixtures/openapi/example.yaml")),
        sample_path: None,
        project: None,
    }
}

fn file_contents<'a>(artifacts: &'a types::DraftArtifacts, bundle_relative_path: &str) -> &'a str {
    artifacts
        .files
        .iter()
        .find(|file| file.bundle_relative_path == bundle_relative_path)
        .unwrap_or_else(|| panic!("expected a draft file at {bundle_relative_path}"))
        .contents
        .as_str()
}

fn assert_adjacent(text: &str, comment: &str, next_line_contains: &str) {
    let lines: Vec<&str> = text.lines().collect();
    let comment_index = lines
        .iter()
        .position(|line| line.contains(comment))
        .unwrap_or_else(|| panic!("expected a line containing {comment:?} in:\n{text}"));
    let next = lines
        .get(comment_index + 1)
        .unwrap_or_else(|| panic!("expected a line after {comment:?} in:\n{text}"));
    assert!(
        next.contains(next_line_contains),
        "expected the line after {comment:?} to contain {next_line_contains:?}, got {next:?}"
    );
}

#[test]
fn response_schema_parses_and_carries_adjacent_annotations() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");

    let parsed: serde_norway::Value =
        serde_norway::from_str(response_schema).expect("response schema parses as YAML");
    assert!(parsed.is_mapping());

    assert_adjacent(
        response_schema,
        "# TODO(evidencectl): /results needs maxItems",
        "results:",
    );
    assert_adjacent(
        response_schema,
        "# TODO(evidencectl): /results/*/status needs string length bounds",
        "status:",
    );
    assert_adjacent(
        response_schema,
        "# derived from the OpenAPI schema",
        "total:",
    );

    // event_date needs no bound comment: `format: date` alone satisfies the
    // subset, so no BoundNeed exists for it in the fixture.
    let event_date_index = response_schema
        .lines()
        .position(|line| line.trim() == "event_date:")
        .expect("event_date property present");
    let preceding = response_schema.lines().nth(event_date_index - 1).unwrap();
    assert!(
        !preceding.contains("TODO(evidencectl)") && !preceding.contains("derived from"),
        "event_date should carry no bound annotation, got preceding line {preceding:?}"
    );
}

/// A flow sequence makes `,`, `[`, `]`, `{` and `}` significant anywhere in a
/// member, not only at its start: an unquoted `pending, review` would parse as
/// two enumeration members.
#[test]
fn a_flow_list_member_containing_a_comma_stays_one_member() {
    let mut inputs = base_inputs();
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": [],
            "properties": {
                "status": {"type": "string", "enum": ["pending, review", "closed"]}
            }
        }),
        unresolved: Vec::new(),
    };
    inputs.needs = Vec::new();
    inputs.selection = vec!["/status".to_owned(), "/a,b".to_owned()];

    let artifacts = emit::draft(&inputs).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");
    let parsed: serde_norway::Value =
        serde_norway::from_str(response_schema).expect("response schema parses as YAML");
    let enumeration = parsed["properties"]["status"]["enum"]
        .as_sequence()
        .expect("enum is a sequence");
    assert_eq!(enumeration.len(), 2, "got {enumeration:?}");
    assert_eq!(enumeration[0].as_str(), Some("pending, review"));

    let block: serde_norway::Value =
        serde_norway::from_str(&artifacts.source_block).expect("source block parses as YAML");
    let projection = block["sources"]["search-a"]["request"]["projection"]
        .as_sequence()
        .expect("projection is a sequence");
    assert_eq!(projection.len(), 2, "got {projection:?}");
    assert_eq!(projection[1].as_str(), Some("/a,b"));
}

/// A bound demanded of an array's items node belongs above `items:`; without
/// it the only annotation-carrying place is the object-properties loop, which
/// an array of scalars never reaches.
#[test]
fn a_bound_on_an_array_items_node_is_annotated_above_items() {
    let mut inputs = base_inputs();
    let unresolved = vec![BoundNeed {
        pointer: "/tags/*".to_owned(),
        kind: BoundKind::StringLength,
        suggestion: None,
    }];
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": [],
            "properties": {
                "tags": {
                    "type": "array",
                    "minItems": 0,
                    "maxItems": 8,
                    "items": {"type": "string"}
                }
            }
        }),
        unresolved: unresolved.clone(),
    };
    inputs.needs = unresolved;
    inputs.selection = vec!["/tags/*".to_owned()];

    let artifacts = emit::draft(&inputs).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");
    assert_adjacent(
        response_schema,
        "# TODO(evidencectl): /tags/* needs string length bounds",
        "items:",
    );
}

/// `uniqueItems` and an array `const` narrow the accepted response, and the
/// narrowing stage deliberately carries both through; dropping them here would
/// widen the drafted schema past what the specification stated.
#[test]
fn an_array_keeps_unique_items_and_a_constant() {
    let mut inputs = base_inputs();
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": [],
            "properties": {
                "tags": {
                    "type": "array",
                    "minItems": 0,
                    "maxItems": 8,
                    "uniqueItems": true,
                    "const": ["alpha", "beta"],
                    "items": {"type": "string", "maxLength": 16}
                }
            }
        }),
        unresolved: Vec::new(),
    };
    inputs.needs = Vec::new();
    inputs.selection = vec!["/tags/*".to_owned()];

    let artifacts = emit::draft(&inputs).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");
    let parsed: serde_norway::Value =
        serde_norway::from_str(response_schema).expect("response schema parses as YAML");
    assert_eq!(
        parsed["properties"]["tags"]["uniqueItems"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["properties"]["tags"]["const"]
            .as_sequence()
            .map(Vec::len),
        Some(2)
    );
}

#[test]
fn facts_schema_stub_is_minimal_and_parses() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let facts_schema = file_contents(&artifacts, "schemas/search-a-facts.schema.yaml");

    let parsed: serde_norway::Value =
        serde_norway::from_str(facts_schema).expect("facts schema parses as YAML");
    let mapping = parsed.as_mapping().expect("facts schema is a mapping");
    assert_eq!(
        mapping
            .get(serde_norway::Value::String("type".to_owned()))
            .and_then(|v| v.as_str()),
        Some("object")
    );
    assert_eq!(
        mapping
            .get(serde_norway::Value::String(
                "additionalProperties".to_owned()
            ))
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    let required = mapping
        .get(serde_norway::Value::String("required".to_owned()))
        .and_then(|v| v.as_sequence())
        .expect("required is a sequence");
    assert_eq!(required.len(), 1);
    assert_eq!(required[0].as_str(), Some("placeholder_fact"));

    let properties = mapping
        .get(serde_norway::Value::String("properties".to_owned()))
        .and_then(|v| v.as_mapping())
        .expect("properties is a mapping");
    assert_eq!(properties.len(), 1);
    assert!(properties.contains_key(serde_norway::Value::String("placeholder_fact".to_owned())));

    assert!(facts_schema.contains("TODO(evidencectl)"));
}

/// The parameters schema stub stays an empty-properties draft (the closed
/// Version 1 subset admits no placeholder property), but it must carry a
/// must-edit comment: without one, the schema-node validator's opaque
/// "schema objects must declare bounded properties" is the reader's only
/// signal that this file needs attention.
#[test]
fn parameters_schema_stub_is_empty_but_carries_a_must_edit_comment() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let parameters_schema = file_contents(&artifacts, "schemas/search-a-parameters.schema.yaml");

    assert!(parameters_schema.contains("TODO(evidencectl)"));
    assert!(parameters_schema.contains("http-json"));

    let parsed: serde_norway::Value =
        serde_norway::from_str(parameters_schema).expect("parameters schema parses as YAML");
    let mapping = parsed.as_mapping().expect("parameters schema is a mapping");
    let properties = mapping
        .get(serde_norway::Value::String("properties".to_owned()))
        .and_then(|v| v.as_mapping())
        .expect("properties is a mapping");
    assert!(
        properties.is_empty(),
        "the draft must stay a must-edit stub, not a placeholder property"
    );
}

#[test]
fn extract_script_uses_get_path_for_every_selected_leaf_with_wildcard_substitution() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let script = file_contents(&artifacts, "adapters/search-a-extract.rhai");

    assert!(script.contains(r#"get_path(source_response, "/total")"#));
    assert!(script.contains(r#"get_path(source_response, "/event_date")"#));
    // The extended pointer's `*` becomes `0` in the plain get_path pointer.
    assert!(script.contains(r#"get_path(source_response, "/results/0/status")"#));
    assert_eq!(script.matches("is_missing(leaf_").count(), 3);

    // A selection under an array gets a commented loop sketch.
    assert!(script.contains("for element_1 in items_1 {"));
    assert!(!script.contains(r#"source_response["total"]"#));

    assert!(script.contains("fn extract(source_response, context) {"));
}

/// The commented loop sketch is read by an operator and then pasted, so it may
/// only use constructs the runtime's Rhai engine actually registers: ranges
/// (`..`) are disabled, `len` is a property getter rather than a method, and
/// no operator concatenates a string with an integer.
#[test]
fn the_array_loop_sketch_uses_only_constructs_the_runtime_registers() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let script = file_contents(&artifacts, "adapters/search-a-extract.rhai");

    assert!(!script.contains("0.."), "ranges are disabled: {script}");
    assert!(!script.contains(".len()"), "len is a getter: {script}");
    assert!(
        !script.contains("+ index"),
        "string + integer has no operator: {script}"
    );
    // The array is reached by its own pointer and iterated directly.
    assert!(
        script.contains(r#"//     let items_1 = get_path(source_response, "/results");"#),
        "the sketch must read the array by its own pointer: {script}"
    );
    assert!(
        script.contains(r#"//     if !is_missing(items_1) {"#),
        "the sketch must guard an absent array: {script}"
    );
    assert!(
        script.contains(r#"//             let value = get_path(element_1, "/status");"#),
        "the sketch must read the leaf from each element: {script}"
    );
}

/// A pointer crossing two arrays names each array by its own pointer: the
/// segment before the first `*` says nothing about the inner one.
#[test]
fn a_nested_array_loop_sketch_names_every_array_it_crosses() {
    let mut inputs = base_inputs();
    inputs.selection = vec!["/results/*/tags/*".to_owned()];
    let artifacts = emit::draft(&inputs).expect("draft");
    let script = file_contents(&artifacts, "adapters/search-a-extract.rhai");

    assert!(
        script.contains(r#"let items_1 = get_path(source_response, "/results");"#),
        "the outer array is /results: {script}"
    );
    assert!(
        script.contains(r#"let items_2 = get_path(element_1, "/tags");"#),
        "the inner array is /tags, reached from an outer element: {script}"
    );
    assert!(
        script.contains("element_2 is the value at /results/*/tags/*"),
        "the innermost element is the selected value: {script}"
    );
}

#[test]
fn get_path_byte_ceiling_is_enforced_and_names_the_pointer() {
    let mut inputs = base_inputs();
    let long_segment = "x".repeat(300);
    let long_pointer = format!("/{long_segment}");
    inputs.selection = vec![long_pointer.clone()];

    let error = emit::draft(&inputs).expect_err("oversized pointer must be rejected");
    let message = format!("{error:#}");
    assert!(message.contains(&long_pointer) || message.contains("byte"));
    assert!(message.contains("256"));
}

#[test]
fn get_path_segment_ceiling_is_enforced_and_names_the_pointer() {
    let mut inputs = base_inputs();
    let segments: Vec<String> = (0..17).map(|n| format!("s{n}")).collect();
    let deep_pointer = format!("/{}", segments.join("/"));
    inputs.selection = vec![deep_pointer.clone()];

    let error = emit::draft(&inputs).expect_err("pointer with too many segments must be rejected");
    let message = format!("{error:#}");
    assert!(message.contains(&deep_pointer));
    assert!(message.contains("16"));
}

#[test]
fn source_block_parses_and_carries_only_mechanical_source_facts() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let parsed: serde_norway::Value =
        serde_norway::from_str(&artifacts.source_block).expect("source block parses as YAML");
    assert!(parsed.is_mapping());

    assert!(artifacts.source_block.contains("search-a:"));
    assert!(artifacts.source_block.contains("method: GET"));
    assert!(artifacts.source_block.contains("path: /v1/records"));
    assert!(artifacts.source_block.contains("value: application/json"));
    assert!(artifacts
        .source_block
        .contains("projection: [/total, /event_date, /results/*/status]"));
    assert!(artifacts
        .source_block
        .contains("baseUrl: https://api.example.invalid"));
    assert!(artifacts
        .source_block
        .contains("responseSchema: schemas/search-a-response.schema.yaml"));
    assert!(artifacts
        .source_block
        .contains("extractScript: adapters/search-a-extract.rhai"));
    assert!(artifacts
        .source_block
        .contains("factSchema: schemas/search-a-facts.schema.yaml"));

    let source = &parsed["sources"]["search-a"];
    for governed in [
        "baseUrl",
        "posture",
        "authentication",
        "selectorInputs",
        "prepareScript",
        "adapterParameters",
        "preparationLimits",
    ] {
        assert!(source.get(governed).is_none(), "draft invented {governed}");
    }
}

/// OpenAPI establishes the method, but it does not establish the adopter's
/// bounded preparation policy.
#[test]
fn a_get_source_omits_request_channel_policy() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let block = &artifacts.source_block;

    assert!(block.contains("method: GET"), "{block}");
    assert!(!block.contains("query:"), "{block}");
    assert!(!block.contains("jsonBody:"), "{block}");
    assert!(!block.contains("maximumQueryPairs:"), "{block}");
}

#[test]
fn a_post_source_omits_request_channel_policy() {
    let mut inputs = base_inputs();
    inputs.operation.method = "POST".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let block = &artifacts.source_block;

    assert!(block.contains("method: POST"), "{block}");
    assert!(!block.contains("query:"), "{block}");
    assert!(!block.contains("jsonBody:"), "{block}");
    assert!(!block.contains("maximumQueryPairs:"), "{block}");
}

/// The runtime's fixed-request method admits GET and POST only.
#[test]
fn a_method_outside_the_runtime_enum_is_refused_by_name() {
    let mut inputs = base_inputs();
    inputs.operation.method = "PATCH".to_owned();

    let error = emit::draft(&inputs).expect_err("PATCH is not an admitted method");
    let message = format!("{error:#}");
    assert!(message.contains("PATCH"), "{message}");
    assert!(
        message.contains("GET") && message.contains("POST"),
        "{message}"
    );
}

/// A templated OpenAPI path cannot be a `path:`, which the runtime rejects on
/// `{` and `}`. It becomes a `pathTemplate:` without inventing bindings.
#[test]
fn a_templated_path_becomes_a_path_template_without_bindings() {
    let mut inputs = base_inputs();
    inputs.operation.path = "/v1/records/{id}".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let block = &artifacts.source_block;

    let parsed: serde_norway::Value =
        serde_norway::from_str(block).expect("source block parses as YAML");
    assert!(parsed.is_mapping());

    assert!(block.contains("pathTemplate: /v1/records/{id}"), "{block}");
    assert!(!block.contains("path: /v1/records/{id}"), "{block}");
    assert!(!block.contains("pathBindings:"), "{block}");
}

/// `baseUrl` is validated as an origin: any path the OpenAPI server URL
/// carries has to move onto the request path instead of staying in the origin.
#[test]
fn a_server_path_prefix_moves_onto_the_request_path() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = emit::split_server_url("https://api.example.invalid:8443/v1/");
    inputs.operation.path = "/records".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let block = &artifacts.source_block;

    assert!(
        block.contains("baseUrl: https://api.example.invalid:8443\n"),
        "{block}"
    );
    assert!(block.contains("path: /v1/records"), "{block}");
}

#[test]
fn a_server_path_prefix_moves_onto_a_path_template_too() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = emit::split_server_url("https://api.example.invalid/v1");
    inputs.operation.path = "/records/{id}".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");

    assert!(
        artifacts
            .source_block
            .contains("pathTemplate: /v1/records/{id}"),
        "{}",
        artifacts.source_block
    );
}

/// A server URL with template variables names no single origin, so the draft
/// falls back to the placeholder rather than emitting an unusable baseUrl.
#[test]
fn a_server_url_with_variables_yields_no_base_url_suggestion() {
    assert!(emit::split_server_url("https://{tenant}.example.invalid/v1").is_none());
    assert!(emit::split_server_url("/relative/only").is_none());

    let split = emit::split_server_url("https://api.example.invalid").expect("plain origin splits");
    assert_eq!(split.base_url, "https://api.example.invalid");
    assert_eq!(split.path_prefix, "");
}

/// Acquisition posture is a governed decision that OpenAPI cannot make.
#[test]
fn the_draft_omits_acquisition_posture() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let block = &artifacts.source_block;

    assert!(!block.contains("posture:"), "{block}");
}

#[test]
fn source_block_leaves_base_url_absent_without_a_suggestion() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = None;
    let artifacts = emit::draft(&inputs).expect("draft");

    assert!(artifacts
        .source_block
        .contains("OpenAPI document gives no fixed origin"));
    assert!(!artifacts.source_block.contains("baseUrl:"));
}

#[test]
fn an_explicit_base_url_is_active_and_overrides_the_openapi_suggestion() {
    let mut inputs = base_inputs();
    inputs.base_url = Some("http://127.0.0.1:4010".to_owned());
    let artifacts = emit::draft(&inputs).expect("draft");
    let parsed: serde_norway::Value =
        serde_norway::from_str(&artifacts.source_block).expect("source block parses as YAML");

    assert_eq!(
        parsed["sources"]["search-a"]["baseUrl"].as_str(),
        Some("http://127.0.0.1:4010")
    );
    assert!(!artifacts.source_block.contains("api.example.invalid"));
    assert!(artifacts
        .equivalent_command
        .contains("--base-url http://127.0.0.1:4010"));
    assert!(!artifacts.report.contains("source origin, posture"));
}

#[test]
fn write_into_project_creates_directories_and_writes_every_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = temp.path().join("project");
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let written = emit::write_into_project(&project, &artifacts.files).expect("write");
    assert_eq!(written.len(), 5);

    for file in &artifacts.files {
        let path = project.join("bundle").join(&file.bundle_relative_path);
        assert!(path.exists(), "expected {path:?} to exist");
        let on_disk = std::fs::read_to_string(&path).expect("read written file");
        assert_eq!(on_disk, file.contents);
    }
}

#[test]
fn write_into_project_refuses_all_collisions_and_writes_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = temp.path().join("project");
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let response_path = project
        .join("bundle")
        .join("schemas/search-a-response.schema.yaml");
    let facts_path = project
        .join("bundle")
        .join("schemas/search-a-facts.schema.yaml");
    std::fs::create_dir_all(response_path.parent().unwrap()).expect("mkdir");
    std::fs::write(&response_path, b"pre-existing\n").expect("seed collision file 1");
    std::fs::write(&facts_path, b"pre-existing\n").expect("seed collision file 2");

    let error =
        emit::write_into_project(&project, &artifacts.files).expect_err("must refuse to overwrite");
    let message = error.to_string();
    assert!(message.contains(&response_path.display().to_string()));
    assert!(message.contains(&facts_path.display().to_string()));

    let extract_path = project
        .join("bundle")
        .join("adapters/search-a-extract.rhai");
    assert!(
        !extract_path.exists(),
        "a non-colliding file must not be written when any file collides"
    );
    // The pre-existing collision files must be untouched.
    assert_eq!(
        std::fs::read_to_string(&response_path).unwrap(),
        "pre-existing\n"
    );
}

/// A value the operator typed is not a value the pipeline derived, and must
/// not be reported as one.
#[test]
fn an_operator_chosen_bound_is_reported_as_chosen_not_derived() {
    let mut inputs = base_inputs();
    inputs.narrowed.unresolved = Vec::new();
    inputs.needs = vec![BoundNeed {
        pointer: "/total".to_owned(),
        kind: BoundKind::IntegerRange,
        suggestion: Some(SuggestedBound {
            values: BoundValues::IntegerRange {
                minimum: 0,
                maximum: 1_000_000,
            },
            provenance: Provenance::Operator,
        }),
    }];

    let artifacts = emit::draft(&inputs).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");
    assert_adjacent(response_schema, "# chosen at the prompt", "total:");
    assert!(
        !response_schema.contains("# derived from"),
        "{response_schema}"
    );

    assert!(
        artifacts.report.contains("Chosen at the prompt:"),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts.report.contains("Derived automatically: none."),
        "an operator's own answer is not a derivation: {}",
        artifacts.report
    );
}

/// Only a need whose accepted value differs from the suggestion is
/// reattributed: adopting a suggestion unchanged keeps its real provenance.
#[test]
fn only_an_edited_or_invented_bound_is_reattributed_to_the_operator() {
    let mut needs = needs_fixture();
    let mut resolutions: std::collections::BTreeMap<(String, BoundKind), BoundValues> =
        std::collections::BTreeMap::new();
    // Adopted unchanged.
    resolutions.insert(
        ("/total".to_owned(), BoundKind::IntegerRange),
        BoundValues::IntegerRange {
            minimum: 0,
            maximum: 1_000_000,
        },
    );
    // Answered where nothing was suggested.
    resolutions.insert(
        ("/results".to_owned(), BoundKind::ArrayMaxItems),
        BoundValues::MaxItems(32),
    );
    // Edited away from the suggestion.
    resolutions.insert(
        ("/results/*/status".to_owned(), BoundKind::StringLength),
        BoundValues::StringLength {
            min_length: 1,
            max_length: 128,
        },
    );

    emit::attribute_operator_edits(&mut needs, &resolutions);

    assert_eq!(
        needs[0].suggestion.as_ref().map(|s| &s.provenance),
        Some(&Provenance::Spec)
    );
    assert_eq!(
        needs[1].suggestion.as_ref().map(|s| &s.provenance),
        Some(&Provenance::Operator)
    );
    assert_eq!(
        needs[1].suggestion.as_ref().map(|s| &s.values),
        Some(&BoundValues::MaxItems(32))
    );
    assert_eq!(
        needs[2].suggestion.as_ref().map(|s| &s.provenance),
        Some(&Provenance::Operator)
    );
}

/// The report must name the governed decisions absent from a mechanical draft.
#[test]
fn the_report_names_omitted_governed_source_decisions() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    assert!(
        artifacts
            .report
            .contains("source origin, posture, authentication, selector bindings"),
        "{}",
        artifacts.report
    );
}

#[test]
fn equivalent_command_is_deterministic_with_the_documented_flag_order() {
    let mut inputs = base_inputs();
    inputs.sample_path = Some(PathBuf::from("tests/fixtures/samples/example.json"));
    inputs.project = Some(PathBuf::from("/tmp/example-project"));

    let first = emit::draft(&inputs).expect("draft").equivalent_command;
    let second = emit::draft(&inputs).expect("draft").equivalent_command;
    assert_eq!(first, second, "equivalent_command must be deterministic");

    let expected = "evidencectl source suggest \
--operation 'GET /v1/records' \
--status 200 \
--media-type application/json \
--sample tests/fixtures/samples/example.json \
--source-id search-a \
--project /tmp/example-project \
--select /total \
--select /event_date \
--select '/results/*/status'";
    assert_eq!(first, expected);
}

/// The reproduce line is meant to be pasted into a shell. A projection pointer
/// carries `*`, which an interactive zsh expands (and aborts on when nothing
/// matches), so every value a shell would rewrite is quoted.
#[test]
fn the_reproduce_command_quotes_every_value_a_shell_would_rewrite() {
    let mut inputs = base_inputs();
    inputs.selection = vec!["/results/*/status".to_owned(), "/a?b".to_owned()];
    inputs.openapi = SpecSource::File(PathBuf::from("/tmp/spec (copy).yaml"));

    let command = emit::draft(&inputs).expect("draft").equivalent_command;
    assert!(
        command.contains("--select '/results/*/status'"),
        "{command}"
    );
    assert!(command.contains("--select '/a?b'"), "{command}");
    assert!(
        command.contains("--openapi '/tmp/spec (copy).yaml'"),
        "{command}"
    );
    assert!(
        !command.contains("--select /results/*/status"),
        "a bare glob must not survive into the reproduce line: {command}"
    );
}

#[test]
fn equivalent_command_omits_optional_flags_when_absent() {
    let inputs = base_inputs();
    let command = emit::draft(&inputs).expect("draft").equivalent_command;
    assert!(!command.contains("--sample"));
    assert!(!command.contains("--project"));
}

/// A stub `evidence` that identifies itself as this build's runtime, the
/// handshake [`emit::verify`] performs before it delegates anything, and runs
/// `script` for every other invocation.
#[cfg(unix)]
fn write_stub_evidence(dir: &Path, script: &str) -> PathBuf {
    write_stub_reporting(dir, registry_platform_buildinfo::DISPLAY_VERSION, script)
}

/// The same stub, reporting `version` when asked to identify itself, so a
/// test can present a runtime this build does not delegate to.
#[cfg(unix)]
fn write_stub_reporting(dir: &Path, version: &str, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let body = script.strip_prefix("#!/bin/sh\n").unwrap_or(script);
    let contents = format!(
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf 'evidence {version}\\n'; exit 0; fi\n{body}"
    );
    let path = dir.join("evidence");
    std::fs::write(&path, contents).expect("write stub evidence script");
    let mut permissions = std::fs::metadata(&path).expect("stat stub").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod stub");
    path
}

/// [`emit::verify`] against a stub this process only just wrote.
///
/// Linux refuses to execute a file while any process holds it open for
/// writing. Every test below writes an executable and immediately runs it, so
/// a sibling test that forks in the window between this thread's write and its
/// exec hands its child an inherited descriptor to the stub, and the exec
/// fails with `ETXTBSY`. The stub is correct and the descriptor closes on the
/// child's own exec, so the only thing to do is wait for it. macOS does not
/// enforce this, which is why the flake only ever appeared in CI.
///
/// The wait belongs here rather than in `emit::verify`: a deployment runs an
/// `evidence` binary nobody is writing, so the retry would be dead weight in
/// the product and would mask a genuinely locked binary.
#[cfg(unix)]
fn verify_stub(project: &Path, stub: &Path) -> CheckClassification {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match emit::verify(project, Some(stub)) {
            Ok(classification) => return classification,
            Err(error) if is_executable_busy(&error) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("verify: {error:#}"),
        }
    }
}

/// True when `error` was caused by an exec the kernel refused because the file
/// is still open for writing somewhere.
#[cfg(unix)]
fn is_executable_busy(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::ExecutableFileBusy)
}

#[cfg(unix)]
#[test]
fn verify_refuses_a_runtime_that_reports_another_version() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");
    let checked = temp.path().join("checked");
    let stub = write_stub_reporting(
        temp.path(),
        "0.0.0-other",
        &format!(
            "#!/bin/sh\nprintf 'checked\\n' > {}\nexit 0\n",
            checked.display()
        ),
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let error = loop {
        match emit::verify(&project, Some(&stub)) {
            Ok(classification) => panic!("a foreign runtime was trusted: {classification:?}"),
            Err(error) if is_executable_busy(&error) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => break error,
        }
    };

    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("0.0.0-other"),
        "the refusal names the reported version: {rendered}"
    );
    assert!(
        rendered.contains(registry_platform_buildinfo::DISPLAY_VERSION),
        "the refusal names this build: {rendered}"
    );
    assert!(
        !checked.exists(),
        "a foreign runtime was asked to check the draft"
    );
}

/// The race [`verify_stub`] exists for, made deterministic: hold the stub open
/// for writing exactly as a forked sibling would, and release it only after
/// the first exec has already been refused.
///
/// Linux only. macOS executes a file that is open for writing, so the same
/// test there would pass whether or not [`verify_stub`] retries, and would
/// report coverage it does not have.
#[cfg(target_os = "linux")]
#[test]
fn verify_waits_out_a_stub_still_held_open_for_writing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let stub = write_stub_evidence(temp.path(), "#!/bin/sh\nexit 0\n");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    let held = std::fs::OpenOptions::new()
        .write(true)
        .open(&stub)
        .expect("hold the stub open for writing");
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(held);
    });

    assert_eq!(
        verify_stub(&project, &stub),
        CheckClassification::BundleAccepted
    );
}

#[cfg(unix)]
#[test]
fn verify_classifies_a_successful_check_as_bundle_accepted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let stub = write_stub_evidence(temp.path(), "#!/bin/sh\nexit 0\n");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    assert_eq!(
        verify_stub(&project, &stub),
        CheckClassification::BundleAccepted
    );
}

#[cfg(unix)]
#[test]
fn verify_classifies_a_deployment_message_as_bundle_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let script = "#!/bin/sh\nprintf 'evidence: deployment configuration is invalid: artifact evidence.yaml: unknown field\\n' >&2\nexit 1\n";
    let stub = write_stub_evidence(temp.path(), script);
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    let classification = verify_stub(&project, &stub);
    match classification {
        CheckClassification::BundleRejected { stderr } => {
            assert!(stderr.contains("deployment configuration is invalid"));
        }
        other => panic!("expected BundleRejected, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn verify_classifies_a_runtime_initialization_message_as_secrets_unprovisioned() {
    let temp = tempfile::tempdir().expect("tempdir");
    let script =
        "#!/bin/sh\nprintf 'evidence: runtime signing initialization failed\\n' >&2\nexit 1\n";
    let stub = write_stub_evidence(temp.path(), script);
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    let classification = verify_stub(&project, &stub);
    assert_eq!(classification, CheckClassification::SecretsUnprovisioned);
}

// --- Escaping and pointer rendering -------------------------------------

/// The reproduce line is documented as paste-ready. A path carrying `$` or a
/// backtick must therefore reach the shell as literal text: unquoted, `$HOME`
/// expands and a backtick pair runs a command, so the pasted line reproduces
/// something other than the run it claims to reproduce.
#[test]
fn the_reproduce_line_quotes_shell_expansion_characters() {
    let mut inputs = base_inputs();
    inputs.openapi = SpecSource::File(PathBuf::from("/srv/specs/$HOME/records`id`.yaml"));
    let artifacts = emit::draft(&inputs).expect("draft");

    assert!(
        artifacts
            .equivalent_command
            .contains("'/srv/specs/$HOME/records`id`.yaml'"),
        "expansion characters must be single-quoted: {}",
        artifacts.equivalent_command
    );
}

/// A property name may legally contain a double quote or a backslash. Both
/// terminate or escape inside a Rhai string literal, so an unescaped one
/// produces an extract script that does not parse, or parses as something
/// other than the pointer it was drafted from.
#[test]
fn the_extract_script_escapes_quotes_in_a_pointer() {
    let mut inputs = base_inputs();
    inputs.selection = vec![r#"/say"hi"#.to_owned(), r"/back\slash".to_owned()];
    let artifacts = emit::draft(&inputs).expect("draft");
    let extract = file_contents(&artifacts, "adapters/search-a-extract.rhai");

    assert!(
        extract.contains(r#"get_path(source_response, "/say\"hi")"#),
        "a double quote must be escaped in the Rhai literal:\n{extract}"
    );
    assert!(
        extract.contains(r#"get_path(source_response, "/back\\slash")"#),
        "a backslash must be escaped in the Rhai literal:\n{extract}"
    );
}

/// The same applies to the drafted YAML: a double-quoted scalar carrying a raw
/// newline or tab folds, silently changing the value the runtime reads.
#[test]
fn drafted_yaml_escapes_control_characters_in_a_scalar() {
    let mut inputs = base_inputs();
    inputs.media_type = "application/json\nx-injected: true".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let source_block = artifacts
        .files
        .iter()
        .find(|file| file.bundle_relative_path.ends_with(".yaml"))
        .map(|file| file.contents.clone())
        .unwrap_or_default();
    let combined = format!("{}\n{}", artifacts.source_block, source_block);

    assert!(
        combined.contains(r"application/json\nx-injected"),
        "a newline must be escaped rather than folded:\n{combined}"
    );
    // A raw newline inside the quoted scalar would make the injected key a
    // sibling mapping entry.
    assert!(
        !combined.contains("\nx-injected: true"),
        "the scalar must not break out into its own mapping key:\n{combined}"
    );
}

/// Emitted paths are project-relative and never refer to removed source-tree
/// templates.
#[test]
fn emitted_paths_are_project_relative() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let all = artifacts
        .files
        .iter()
        .fold(artifacts.source_block.clone(), |mut text, file| {
            text.push('\n');
            text.push_str(&file.contents);
            text
        });

    assert!(all.contains("schemas/search-a-response.schema.yaml"));
    assert!(all.contains("adapters/search-a-extract.rhai"));
    assert!(
        !all.contains("templates/bundle/"),
        "an evidencectl source path is not a path in the adopter's project:\n{all}"
    );
}

/// A response body that is itself an array still needs a `maxItems`. The bound
/// belongs to the root node, which has no property to hang a comment on and no
/// pointer text of its own.
#[test]
fn a_root_level_array_carries_its_own_bound_annotation() {
    let mut inputs = base_inputs();
    inputs.selection = vec!["/*/trackingId".to_owned()];
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": [],
                "properties": {"trackingId": {"type": "string", "minLength": 0, "maxLength": 64}}
            }
        }),
        unresolved: vec![BoundNeed {
            pointer: String::new(),
            kind: BoundKind::ArrayMaxItems,
            suggestion: None,
        }],
    };
    inputs.needs = vec![BoundNeed {
        pointer: String::new(),
        kind: BoundKind::ArrayMaxItems,
        suggestion: None,
    }];

    let artifacts = emit::draft(&inputs).expect("draft");
    let response_schema = file_contents(&artifacts, "schemas/search-a-response.schema.yaml");

    assert!(
        response_schema.contains("TODO(evidencectl): (response root) needs maxItems"),
        "the root array's own bound must be annotated:\n{response_schema}"
    );
    assert!(
        !response_schema.contains("TODO(evidencectl):  "),
        "an empty pointer must not render as blank text:\n{response_schema}"
    );
    assert!(
        !artifacts.report.contains("TODO(evidencectl):  "),
        "an empty pointer must not render as blank text in the report:\n{}",
        artifacts.report
    );
}

/// A rejected bundle and unprovisioned secrets are opposite outcomes: one means
/// the draft is wrong, the other means the draft is fine and the operator has
/// not generated keys yet. Classifying a bundle rejection as the latter reports
/// success for a draft the runtime refused.
#[cfg(unix)]
#[test]
fn verify_never_classifies_a_bundle_rejection_as_unprovisioned_secrets() {
    for stage in ["bundle", "source", "rate-limit"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let script = format!(
            "#!/bin/sh\nprintf 'evidence: runtime {stage} initialization failed\\n' >&2\nexit 1\n"
        );
        let stub = write_stub_evidence(temp.path(), &script);
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).expect("mkdir project");

        let classification = verify_stub(&project, &stub);
        assert!(
            matches!(classification, CheckClassification::BundleRejected { .. }),
            "a {stage}-stage failure is a rejected bundle, got {classification:?}"
        );
    }
}

/// A future runtime may append a reason to a secret-stage message. The
/// classification must survive that without loosening into a prefix match that
/// also catches the bundle stage.
#[cfg(unix)]
#[test]
fn verify_classifies_a_secret_stage_message_carrying_a_reason() {
    let temp = tempfile::tempdir().expect("tempdir");
    let script = "#!/bin/sh\nprintf 'evidence: runtime audit initialization failed: the audit chain head does not verify\\n' >&2\nexit 1\n";
    let stub = write_stub_evidence(temp.path(), script);
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    let classification = verify_stub(&project, &stub);
    assert_eq!(classification, CheckClassification::SecretsUnprovisioned);
}
