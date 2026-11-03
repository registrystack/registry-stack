//! Emit stage: draft artifacts from a narrowed response schema, write them
//! into a deployment project, and classify `evidence check` output.
//!
//! Inputs are built here as `NarrowOutcome`/`EmitInputs` literals rather than
//! produced by the other pipeline stages, so a failure names an emit-stage
//! rule and never a bug in the OpenAPI loader, the sampler, or the narrowing
//! heuristics (all still placeholders as this file is written).
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use registry_evidence_authoring::openapi::types;
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

#[allow(dead_code)]
#[path = "../src/evidence_binary.rs"]
mod evidence_binary;

#[allow(dead_code)]
#[path = "../src/suggest/emit.rs"]
mod emit;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::json;

use emit::{CheckClassification, EmitInputs};
use types::{
    BoundKind, BoundNeed, BoundValues, NarrowOutcome, OperationKey, Provenance, RequestMapping,
    RequestTarget, SelectorReference, SelectorScalarType, SpecSource, SuggestedBound,
};

const ADAPTER_PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: registry_adapter_core::ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            registry_adapter_core::ADAPTER_PACK_API_VERSION,
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
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
        openapi_document: "openapi: 3.1.0\ninfo: {title: Example, version: '1'}\npaths: {}\n"
            .to_owned(),
        sample_path: None,
        project: None,
        request_mappings: Vec::new(),
    }
}

#[test]
fn draft_emits_a_pinned_pack_closure_and_only_a_thin_source_binding() {
    let artifacts = emit::draft(&base_inputs()).expect("pack-backed draft");
    let source: serde_json::Value =
        serde_json::from_str(&artifacts.authoring_source).expect("normalized Source JSON");
    assert_eq!(source["pack"], json!({"id":"search-a","version":"0.1.0"}));
    assert_eq!(source["route"], "search-a");
    assert_eq!(source["connection"], "search-a");
    assert!(source.get("request").is_none());
    assert!(source.get("prepare").is_none());
    assert!(source.get("extract").is_none());

    let pack = file_contents(&artifacts, "adapter-packs/search-a/pack.yaml");
    let typed_pack = typed_pack(pack);
    let findings = registry_adapter_core::check_pack(&typed_pack);
    assert!(
        findings.is_empty(),
        "generated pack must pass current structural admission: {findings:#?}"
    );
    let pack = serde_json::to_value(typed_pack).expect("AdapterPack JSON");
    assert_eq!(pack["openApi"]["path"], "openapi/source.openapi.yaml");
    assert_eq!(pack["sourceRoutes"][0]["id"], "search-a");
    assert!(pack["sourceRoutes"][0].get("evidence").is_some());
    assert_eq!(pack["endpoints"][0]["requestHeaders"], json!(["accept"]));
    for reference in [
        &pack["openApi"],
        &pack["sourceRoutes"][0]["evidence"]["inputsSchema"],
        &pack["sourceRoutes"][0]["evidence"]["factsSchema"],
    ] {
        let path = reference["path"].as_str().expect("pinned path");
        let expected = reference["digest"].as_str().expect("pinned digest");
        let actual = registry_platform_config::sha256_uri(
            file_contents(&artifacts, &format!("adapter-packs/search-a/{path}")).as_bytes(),
        );
        assert_eq!(actual, expected);
    }
    let all = artifacts
        .files
        .iter()
        .map(|file| file.contents.as_str())
        .collect::<String>();
    assert!(!all.contains("source-prepare/v1"));
    assert!(!all.contains("source-extract/v1"));
}

#[test]
fn explicit_path_and_query_mappings_generate_pack_bindings_and_thin_source_inputs() {
    let mut inputs = base_inputs();
    inputs.operation.path = "/v1/records/{record_id}".to_owned();
    let selector = SelectorReference {
        role: "subject".to_owned(),
        profile: "subject-reference-v1".to_owned(),
        field: "reference".to_owned(),
        scalar_type: SelectorScalarType::String,
        maximum_bytes: 128,
    };
    inputs.request_mappings = vec![
        RequestMapping {
            selector: selector.clone(),
            target: RequestTarget::Path("record_id".to_owned()),
        },
        RequestMapping {
            selector,
            target: RequestTarget::Query("reference".to_owned()),
        },
    ];

    let artifacts = emit::draft(&inputs).expect("mapped draft");
    let source: serde_json::Value =
        serde_json::from_str(&artifacts.authoring_source).expect("normalized Source JSON");
    assert_eq!(
        source["inputs"],
        json!({
            "input1":{"selector":{"role":"subject","profile":"subject-reference-v1","field":"reference"}},
            "input2":{"selector":{"role":"subject","profile":"subject-reference-v1","field":"reference"}}
        })
    );
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");
    assert_eq!(to_parameters(&pack)["path"], "/v1/records/{{record_id}}");
    assert_eq!(
        to_parameters(&pack)["pathParameters"]["record_id"]["jsonpath"],
        "$.input1"
    );
    assert_eq!(
        to_parameters(&pack)["query"]["reference"]["jsonpath"],
        "$.input2"
    );
}

#[test]
fn mapped_rendered_path_guard_agrees_with_current_pack_admission() {
    let maximum = format!("/{}", "a".repeat(2047));
    let overlong = format!("/{}", "a".repeat(2048));
    let cases = [
        ("/v1/records", ""),
        ("/v1/records/{record_id}", "/api"),
        ("/v1/exact:record/{record_id}", ""),
        ("/v1/value%20with%20space/{record_id}", ""),
        (maximum.as_str(), ""),
        (overlong.as_str(), ""),
        ("/v1/records/{record_id}/", ""),
        ("/v1//records/{record_id}", ""),
        ("/v1/./records/{record_id}", ""),
        ("/v1/../records/{record_id}", ""),
        ("/v1/récords/{record_id}", ""),
        ("/v1/records/{record_id}?fixed=1", ""),
        ("/v1/records/{record_id}#fragment", ""),
        ("/v1/records\\other/{record_id}", ""),
        ("/v1/%2e/{record_id}", ""),
        ("/v1/%2F/{record_id}", ""),
        ("/v1/%41/{record_id}", ""),
        ("/v1/%GG/{record_id}", ""),
        ("/v1/records/{record_id}", "/api//v2"),
        ("/v1/records/{record_id}", "/api/%2F"),
    ];
    let expected = [
        true, true, true, true, true, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false,
    ];
    for (case, ((path, prefix), expected)) in cases.into_iter().zip(expected).enumerate() {
        let mut inputs = base_inputs();
        inputs.operation.path = path.to_owned();
        inputs.base_url_suggestion =
            emit::split_server_url(&format!("https://api.example.invalid{prefix}"));
        let selector = SelectorReference {
            role: "subject".to_owned(),
            profile: "person-demographics-v1".to_owned(),
            field: "given_name".to_owned(),
            scalar_type: SelectorScalarType::String,
            maximum_bytes: 200,
        };
        inputs.request_mappings = vec![RequestMapping {
            selector: selector.clone(),
            target: RequestTarget::Query("reference".to_owned()),
        }];
        if path.contains("{record_id}") {
            inputs.request_mappings.push(RequestMapping {
                selector,
                target: RequestTarget::Path("record_id".to_owned()),
            });
        }
        let rendered = format!("{prefix}{path}");
        let draft = emit::draft(&inputs);
        assert_eq!(
            draft.is_ok(),
            expected,
            "path case {case} ({} bytes): draft {:?}",
            rendered.len(),
            draft.as_ref().err(),
        );
        if let Ok(draft) = draft {
            let pack: serde_json::Value =
                serde_norway::from_str(file_contents(&draft, "adapter-packs/search-a/pack.yaml"))
                    .expect("AdapterPack YAML");
            assert_eq!(
                to_parameters(&pack)["path"],
                rendered.replace('{', "{{").replace('}', "}}")
            );
        }
    }
}

#[test]
fn unmapped_incomplete_path_drafts_remain_available() {
    let mut inputs = base_inputs();
    inputs.operation.path = "/v1/records/{RecordId}/".to_owned();
    let draft = emit::draft(&inputs).expect("unmapped authoring draft");
    assert!(file_contents(
        &draft,
        "adapter-packs/search-a/scripts/search-a-prepare.rhai"
    )
    .contains("TODO(evidencectl)"));
}

#[test]
fn explicit_post_body_mappings_generate_a_closed_json_object() {
    let mut inputs = base_inputs();
    inputs.operation.method = "POST".to_owned();
    inputs.operation.path = "/v1/search".to_owned();
    inputs.request_mappings = vec![
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "reference".to_owned(),
                scalar_type: SelectorScalarType::String,
                maximum_bytes: 128,
            },
            target: RequestTarget::Body("/subject/reference".to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "active".to_owned(),
                scalar_type: SelectorScalarType::Boolean,
                maximum_bytes: 5,
            },
            target: RequestTarget::Body("/subject/active".to_owned()),
        },
    ];

    let artifacts = emit::draft(&inputs).expect("mapped draft");
    let prepare = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-prepare.rhai",
    );
    assert!(prepare.contains("#{"), "{prepare}");
    assert!(prepare.contains(r#""subject": #{"#), "{prepare}");
    assert!(
        prepare.contains(r#""reference": inputs["input1"]"#),
        "{prepare}"
    );
    assert!(
        prepare.contains(r#""active": inputs["input2"]"#),
        "{prepare}"
    );
    assert!(!prepare.contains("TODO(evidencectl)"), "{prepare}");
}

#[test]
fn generated_pack_maps_scalar_queries_and_executes_escaped_json_body_script() {
    let mut inputs = base_inputs();
    inputs.operation.method = "POST".to_owned();
    let quoted_name = "trace\"'\\name";
    inputs.request_mappings = vec![
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "reference".to_owned(),
                scalar_type: SelectorScalarType::String,
                maximum_bytes: 128,
            },
            target: RequestTarget::Query("external-reference".to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "count".to_owned(),
                scalar_type: SelectorScalarType::Integer,
                maximum_bytes: 16,
            },
            target: RequestTarget::Query("count".to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "active".to_owned(),
                scalar_type: SelectorScalarType::Boolean,
                maximum_bytes: 5,
            },
            target: RequestTarget::Query("active".to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "reference".to_owned(),
                scalar_type: SelectorScalarType::String,
                maximum_bytes: 128,
            },
            target: RequestTarget::Query(quoted_name.to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "reference".to_owned(),
                scalar_type: SelectorScalarType::String,
                maximum_bytes: 128,
            },
            target: RequestTarget::Body("/lookup~1key/value~0text".to_owned()),
        },
        RequestMapping {
            selector: SelectorReference {
                role: "subject".to_owned(),
                profile: "person-v1".to_owned(),
                field: "active".to_owned(),
                scalar_type: SelectorScalarType::Boolean,
                maximum_bytes: 5,
            },
            target: RequestTarget::Body("/lookup~1key/required~0flag".to_owned()),
        },
    ];
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack_root = tempfile::tempdir().expect("pack root");
    emit::write_into_project(pack_root.path(), &artifacts.files).expect("write pack closure");
    let pack_directory = pack_root.path().join("adapter-packs/search-a");
    let pack_text = std::fs::read_to_string(pack_directory.join("pack.yaml")).expect("pack YAML");
    let pack = typed_pack(&pack_text);
    let pack_value = serde_json::to_value(&pack).expect("pack JSON");
    let parameters = to_parameters(&pack_value);
    assert_eq!(
        parameters["query"]["external-reference"]["jsonpath"],
        "$.input1"
    );
    assert_eq!(parameters["query"]["count"]["jsonpath"], "$.input2");
    assert_eq!(parameters["query"]["active"]["jsonpath"], "$.input3");
    assert_eq!(parameters["query"][quoted_name]["jsonpath"], "$.input4");
    let mut scripts = registry_adapter_engine::scripts::ScriptSet::default();
    scripts
        .add(
            &pack,
            &pack_directory,
            "scripts/search-a-prepare.rhai",
            "prepare",
        )
        .expect("generated pack script compiles in the current engine");
    let prepared = scripts
        .call(
            &Arc::new(BTreeMap::new()),
            "scripts/search-a-prepare.rhai",
            "prepare",
            &json!({
                "body": {
                    "input1":"a&b=c", "input2":42, "input3":true,
                    "input4":"a&b=c", "input5":"a&b=c", "input6":true
                },
                "headers": {},
                "properties": {}
            }),
        )
        .expect("generated pack body script executes through the current ABI");
    assert_eq!(
        prepared,
        json!({"lookup/key": {"required~flag": true, "value~text": "a&b=c"}})
    );
    let request_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [],
        "properties": {
            "lookup/key": {
                "type": "object",
                "additionalProperties": false,
                "required": ["value~text", "required~flag"],
                "properties": {
                    "value~text": {"type": "string"},
                    "required~flag": {"type": "boolean"}
                }
            }
        }
    });
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&request_schema)
        .expect("request schema compiles");
    assert!(
        validator.is_valid(&prepared),
        "generated request body satisfies the resolved OpenAPI request schema"
    );
}

fn file_contents<'a>(artifacts: &'a types::DraftArtifacts, bundle_relative_path: &str) -> &'a str {
    artifacts
        .files
        .iter()
        .find(|file| file.bundle_relative_path == bundle_relative_path)
        .unwrap_or_else(|| panic!("expected a pack artifact at {bundle_relative_path}"))
        .contents
        .as_str()
}

fn typed_pack(document: &str) -> registry_adapter_core::AdapterPack {
    Reader::new("generated Adapter pack")
        .decode::<registry_adapter_core::AdapterPack>(
            document.as_bytes(),
            &Expect::one(&ADAPTER_PACK_FORMAT),
        )
        .expect("typed AdapterPack YAML")
        .value
}

fn to_parameters(pack: &serde_json::Value) -> &serde_json::Value {
    pack["sourceRoutes"][0]["steps"]
        .as_array()
        .expect("route steps")
        .iter()
        .find_map(|step| step.get("to"))
        .map(|to| &to["parameters"])
        .expect("route to parameters")
}

#[test]
fn response_schema_parses_and_carries_adjacent_annotations() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );

    let parsed: serde_json::Value =
        serde_json::from_str(response_schema).expect("facts schema parses as JSON");
    assert!(parsed.is_object());

    assert!(artifacts.report.contains("/results"));
    assert!(artifacts.report.contains("/results/*/status"));
    assert_eq!(
        parsed["properties"]["total"]["maximum"].as_i64(),
        Some(1_000_000)
    );
    assert_eq!(
        parsed["properties"]["event_date"]["format"].as_str(),
        Some("date")
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
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_schema).expect("facts schema parses as JSON");
    let enumeration = parsed["properties"]["status"]["enum"]
        .as_array()
        .expect("enum is an array");
    assert_eq!(enumeration.len(), 2, "got {enumeration:?}");
    assert_eq!(enumeration[0].as_str(), Some("pending, review"));

    let extract = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-extract.rhai",
    );
    assert!(extract.contains(r#"if "status" in value"#), "{extract}");
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
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(response_schema).unwrap()["properties"]["tags"]
            ["items"]["type"]
            .as_str(),
        Some("string")
    );
    assert!(artifacts.report.contains("/tags/*"));
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
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_schema).expect("facts schema parses as JSON");
    assert_eq!(
        parsed["properties"]["tags"]["uniqueItems"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["properties"]["tags"]["const"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
}

#[test]
fn facts_schema_is_the_closed_selected_projection_and_parses() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let facts_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );

    let parsed: serde_json::Value =
        serde_json::from_str(facts_schema).expect("facts schema parses as JSON");
    assert_eq!(parsed, narrow_outcome_fixture().schema);
    assert!(artifacts.report.contains("private fact"));
}

/// The pack owns a closed input schema whose properties are exactly the thin
/// Source's minimized selector bindings.
#[test]
fn inputs_schema_is_closed_and_matches_source_bindings() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let inputs_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-inputs.schema.json",
    );

    assert!(artifacts.report.contains("pack request mapping"));

    let parsed: serde_json::Value =
        serde_json::from_str(inputs_schema).expect("inputs schema parses as JSON");
    assert_eq!(parsed["additionalProperties"], false);
    assert_eq!(parsed["properties"], json!({}));
    assert_eq!(parsed["required"], json!([]));
}

#[test]
fn extract_script_projects_every_selected_leaf_and_array_without_raw_path_helpers() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let script = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-extract.rhai",
    );

    for field in ["total", "event_date", "results", "status"] {
        assert!(
            script.contains(&format!(r#"if "{field}" in value"#)),
            "{script}"
        );
    }
    assert!(script.contains("for item in value"), "{script}");
    assert!(!script.contains("get_path"), "{script}");
    assert!(script.contains("fn extract(exchange) {"), "{script}");
    assert!(
        script.contains(r#"#{lookup: "matched", facts:"#),
        "{script}"
    );
}

/// The commented loop sketch is read by an operator and then pasted, so it may
/// only use constructs the runtime's Rhai engine actually registers: ranges
/// (`..`) are disabled, `len` is a property getter rather than a method, and
/// no operator concatenates a string with an integer.
#[test]
fn the_array_projector_uses_only_constructs_the_runtime_registers() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let script = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-extract.rhai",
    );

    assert!(!script.contains("0.."), "ranges are disabled: {script}");
    assert!(!script.contains(".len()"), "len is a getter: {script}");
    assert!(
        !script.contains("+ index"),
        "string + integer has no operator: {script}"
    );
    assert!(script.contains("for item in value"), "{script}");
    assert!(script.contains("out.push(project_"), "{script}");
}

/// A pointer crossing two arrays names each array by its own pointer: the
/// segment before the first `*` says nothing about the inner one.
#[test]
fn a_nested_array_projector_names_and_calls_every_array_it_crosses() {
    let mut inputs = base_inputs();
    inputs.selection = vec!["/results/*/tags/*".to_owned()];
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type":"object","additionalProperties":false,"properties":{
                "results":{"type":"array","maxItems":8,"items":{
                    "type":"object","additionalProperties":false,"properties":{
                        "tags":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":64}}
                    }
                }}
            }
        }),
        unresolved: Vec::new(),
    };
    inputs.needs = Vec::new();
    let artifacts = emit::draft(&inputs).expect("draft");
    let script = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-extract.rhai",
    );

    assert_eq!(script.matches("let out = [];").count(), 2, "{script}");
    assert_eq!(script.matches("for item in value").count(), 2, "{script}");
    assert!(
        script.contains(r#"project_1(value["results"])"#),
        "{script}"
    );
    assert!(script.contains(r#"project_3(value["tags"])"#), "{script}");
    assert!(script.contains("out.push(project_2(item))"), "{script}");
    assert!(script.contains("out.push(item)"), "{script}");
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
fn source_block_parses_as_a_thin_pack_route_and_connection_binding() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let parsed: serde_norway::Value =
        serde_norway::from_str(&artifacts.source_block).expect("source block parses as YAML");
    assert!(parsed.is_mapping());

    assert!(artifacts.source_block.contains("search-a:"));
    assert_eq!(
        parsed["sources"]["search-a"]["pack"]["id"].as_str(),
        Some("search-a")
    );
    assert_eq!(
        parsed["sources"]["search-a"]["route"].as_str(),
        Some("search-a")
    );
    assert_eq!(
        parsed["sources"]["search-a"]["connection"].as_str(),
        Some("search-a")
    );
    assert_eq!(
        parsed["sources"]["search-a"]["acquisitionPosture"].as_str(),
        Some("record-transformed")
    );
    assert_eq!(
        parsed["sources"]["search-a"]["inputs"]
            .as_mapping()
            .map(|inputs| inputs.len()),
        Some(0)
    );

    let source = &parsed["sources"]["search-a"];
    for governed in [
        "baseUrl",
        "posture",
        "authentication",
        "request",
        "prepare",
        "extract",
        "limits",
    ] {
        assert!(source.get(governed).is_none(), "draft invented {governed}");
    }
}

/// OpenAPI establishes a safe GET request, but it does not establish query or
/// body bindings that the author did not map.
#[test]
fn an_unmapped_get_pack_omits_uninvented_request_channels() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");
    let parameters = to_parameters(&pack);

    assert_eq!(parameters["httpMethod"], "GET");
    assert!(parameters.get("query").is_none());
    assert!(parameters.get("body").is_none());
    assert!(parameters.get("maximumQueryPairs").is_none());
}

#[test]
fn an_unmapped_post_pack_uses_the_reviewable_body_script_without_query_policy() {
    let mut inputs = base_inputs();
    inputs.operation.method = "POST".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");
    let parameters = to_parameters(&pack);

    assert_eq!(parameters["httpMethod"], "POST");
    assert_eq!(
        parameters["body"]["rhai"]["file"],
        "scripts/search-a-prepare.rhai"
    );
    assert!(parameters.get("query").is_none());
    assert!(parameters.get("maximumQueryPairs").is_none());
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

/// A templated OpenAPI path is written as the pack request template it is. The
/// draft invents no bindings.
#[test]
fn a_templated_path_becomes_a_path_template_without_bindings() {
    let mut inputs = base_inputs();
    inputs.operation.path = "/v1/records/{id}".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");
    let parameters = to_parameters(&pack);

    assert_eq!(parameters["path"], "/v1/records/{{id}}");
    assert!(parameters.get("pathParameters").is_none());
}

/// `baseUrl` is validated as an origin: any path the OpenAPI server URL
/// carries has to move onto the request path instead of staying in the origin.
#[test]
fn a_server_path_prefix_moves_onto_the_request_path() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = emit::split_server_url("https://api.example.invalid:8443/v1/");
    inputs.operation.path = "/records".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");

    assert_eq!(to_parameters(&pack)["path"], "/v1/records");
    assert!(!artifacts.source_block.contains("baseUrl:"));
}

#[test]
fn a_server_path_prefix_moves_onto_a_path_template_too() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = emit::split_server_url("https://api.example.invalid/v1");
    inputs.operation.path = "/records/{id}".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");

    assert_eq!(to_parameters(&pack)["path"], "/v1/records/{{id}}");
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

/// The generated Source and its pack evidence contract must agree on the
/// explicit posture the author is asked to review.
#[test]
fn the_draft_carries_one_consistent_acquisition_posture() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let source: serde_json::Value =
        serde_json::from_str(&artifacts.authoring_source).expect("normalized Source JSON");
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");

    assert_eq!(source["acquisitionPosture"], "record-transformed");
    assert_eq!(
        pack["sourceRoutes"][0]["evidence"]["acquisitionPosture"],
        "record-transformed"
    );
}

#[test]
fn source_block_leaves_base_url_absent_without_a_suggestion() {
    let mut inputs = base_inputs();
    inputs.base_url_suggestion = None;
    let artifacts = emit::draft(&inputs).expect("draft");

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
        parsed["sources"]["search-a"]["connection"].as_str(),
        Some("search-a")
    );
    assert!(!artifacts.source_block.contains("api.example.invalid"));
    assert!(artifacts
        .equivalent_command
        .contains("--base-url http://127.0.0.1:4010"));
    assert!(
        !artifacts.report.contains("Set the source origin."),
        "{}",
        artifacts.report
    );
}

#[test]
fn write_into_project_creates_directories_and_writes_every_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = temp.path().join("project");
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let written = emit::write_into_project(&project, &artifacts.files).expect("write");
    assert_eq!(written.len(), 6);

    for file in &artifacts.files {
        let path = project.join(&file.bundle_relative_path);
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

    let response_path = project.join("adapter-packs/search-a/scripts/search-a-prepare.rhai");
    let facts_path = project.join("adapter-packs/search-a/scripts/search-a-extract.rhai");
    std::fs::create_dir_all(response_path.parent().unwrap()).expect("mkdir");
    std::fs::write(&response_path, b"pre-existing\n").expect("seed collision file 1");
    std::fs::write(&facts_path, b"pre-existing\n").expect("seed collision file 2");

    let error =
        emit::write_into_project(&project, &artifacts.files).expect_err("must refuse to overwrite");
    let message = error.to_string();
    assert!(message.contains(&response_path.display().to_string()));
    assert!(message.contains(&facts_path.display().to_string()));

    let extract_path = project.join("adapter-packs/search-a/pack.yaml");
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

fn authoring_project(root: &Path) -> PathBuf {
    let project = root.join("project");
    std::fs::create_dir(&project).expect("create project");
    std::fs::write(
        project.join("evidence.yaml"),
        include_bytes!("../../../products/evidence/examples/standalone/evidence.yaml"),
    )
    .expect("write evidence.yaml");
    project
}

#[test]
fn write_into_authoring_project_creates_missing_pack_directories() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let artifacts = emit::draft(&base_inputs()).expect("draft");

    let written = emit::write_into_authoring_project(&project, &artifacts).expect("write draft");

    assert_eq!(written.len(), 7);
    for file in &artifacts.files {
        let path = project.join(&file.bundle_relative_path);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read written file"),
            file.contents
        );
    }
    let project_text = std::fs::read_to_string(project.join("evidence.yaml")).expect("project");
    assert!(project_text.contains("search-a:"), "{project_text}");
}

#[test]
fn write_into_authoring_project_refuses_a_collision_without_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let project_before = std::fs::read(project.join("evidence.yaml")).expect("project before");
    let collision = project.join("adapter-packs/search-a/pack.yaml");
    std::fs::create_dir_all(collision.parent().expect("pack parent")).expect("create pack parent");
    std::fs::write(&collision, b"operator-owned\n").expect("seed collision");

    let error = emit::write_into_authoring_project(&project, &artifacts)
        .expect_err("must refuse to overwrite");

    assert!(error.to_string().contains(&collision.display().to_string()));
    assert_eq!(
        std::fs::read(&collision).expect("collision"),
        b"operator-owned\n"
    );
    assert_eq!(
        std::fs::read(project.join("evidence.yaml")).expect("project after"),
        project_before
    );
    assert!(!project.join("adapter-packs/search-a/scripts").exists());
}

#[test]
fn write_into_authoring_project_refuses_a_non_directory_parent_before_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let project_before = std::fs::read(project.join("evidence.yaml")).expect("project before");
    let pack_root = project.join("adapter-packs/search-a");
    std::fs::create_dir_all(&pack_root).expect("create pack root");
    let blocked_parent = pack_root.join("schemas");
    std::fs::write(&blocked_parent, b"operator-owned\n").expect("seed non-directory parent");

    let error = emit::write_into_authoring_project(&project, &artifacts)
        .expect_err("a file cannot be an asset parent");

    assert!(
        error
            .to_string()
            .contains(&blocked_parent.display().to_string()),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(project.join("evidence.yaml")).expect("project after"),
        project_before
    );
    assert_eq!(
        std::fs::read(&blocked_parent).expect("existing parent marker"),
        b"operator-owned\n"
    );
    assert!(!pack_root.join("pack.yaml").exists());
    assert!(!pack_root.join("scripts").exists());
}

#[test]
fn write_into_authoring_project_rolls_back_all_new_assets_after_a_late_duplicate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let mut artifacts = emit::draft(&base_inputs()).expect("draft");
    artifacts.files.push(artifacts.files[0].clone());
    let project_before = std::fs::read(project.join("evidence.yaml")).expect("project before");
    let existing_root = project.join("adapter-packs");
    std::fs::create_dir(&existing_root).expect("create existing pack root");

    let error = emit::write_into_authoring_project(&project, &artifacts)
        .expect_err("the final duplicate must be refused by create_new");

    assert!(error.to_string().contains("pack.yaml"), "{error:#}");
    assert_eq!(
        std::fs::read(project.join("evidence.yaml")).expect("project after"),
        project_before
    );
    assert!(
        existing_root.is_dir(),
        "the existing directory is preserved"
    );
    assert_eq!(
        std::fs::read_dir(&existing_root)
            .expect("existing pack root")
            .count(),
        0,
        "every asset and directory created by the failed write is removed"
    );
}

#[test]
fn write_into_authoring_project_refuses_a_symlink_parent_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let project_before = std::fs::read(project.join("evidence.yaml")).expect("project before");
    let pack_root = project.join("adapter-packs/search-a");
    std::fs::create_dir_all(&pack_root).expect("create pack root");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).expect("create outside directory");
    let linked_parent = pack_root.join("scripts");
    symlink(&outside, &linked_parent).expect("create parent symlink");

    let error = emit::write_into_authoring_project(&project, &artifacts)
        .expect_err("a symlink cannot be an asset parent");

    assert!(
        error
            .to_string()
            .contains(&linked_parent.display().to_string()),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(project.join("evidence.yaml")).expect("project after"),
        project_before
    );
    assert!(!pack_root.join("pack.yaml").exists());
    assert_eq!(
        std::fs::read_dir(&outside)
            .expect("outside directory")
            .count(),
        0,
        "the symlink target must remain untouched"
    );
}

#[test]
fn write_into_authoring_project_refuses_relative_path_escapes_before_writing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project = authoring_project(temp.path());
    let mut artifacts = emit::draft(&base_inputs()).expect("draft");
    artifacts.files[5].bundle_relative_path = "../escaped.openapi.yaml".to_owned();
    let project_before = std::fs::read(project.join("evidence.yaml")).expect("project before");

    let error = emit::write_into_authoring_project(&project, &artifacts)
        .expect_err("a draft path must remain inside the project");

    assert!(error.to_string().contains("project-relative"), "{error:#}");
    assert!(!temp.path().join("escaped.openapi.yaml").exists());
    assert!(!project.join("adapter-packs").exists());
    assert_eq!(
        std::fs::read(project.join("evidence.yaml")).expect("project after"),
        project_before
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
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(response_schema).unwrap()["properties"]["total"]
            ["maximum"]
            .as_i64(),
        Some(1_000_000)
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

/// An unmapped draft already carries a posture, a preparation script, and
/// default endpoint limits. The report must ask the adopter to complete and
/// review those artifacts rather than claiming that they are absent.
#[test]
fn the_unmapped_report_distinguishes_generated_shells_from_remaining_work() {
    let artifacts = emit::draft(&base_inputs()).expect("draft");
    let source: serde_json::Value =
        serde_json::from_str(&artifacts.authoring_source).expect("normalized Source JSON");
    let prepare = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-prepare.rhai",
    );
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");

    assert_eq!(source["acquisitionPosture"], json!("record-transformed"));
    assert_eq!(
        pack["endpoints"][0]["attemptTimeoutMilliseconds"],
        json!(3000)
    );
    assert_eq!(pack["endpoints"][0]["maximumResponseBytes"], json!(65536));
    assert_eq!(source["inputs"], json!({}));
    assert!(source.get("prepare").is_none());
    assert!(source.get("limits").is_none());
    assert!(prepare.contains("TODO(evidencectl)"), "{prepare}");

    assert!(
        artifacts.report.contains("source origin"),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("Review the generated Source posture and default source limits."),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("Complete selector bindings and the pack request mapping."),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("Configure target-owned authentication."),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("adapter-packs/search-a/scripts/search-a-extract.rhai")
            && artifacts.report.contains("target authority"),
        "{}",
        artifacts.report
    );
    assert!(
        !artifacts.report.contains("intentionally absent"),
        "{}",
        artifacts.report
    );
}

/// Explicit mappings generate the selector inputs and pack request mapping.
/// With a chosen origin, all of those inputs exist and the report's remaining
/// work is review, not completion or absence.
#[test]
fn the_mapped_report_names_generated_request_artifacts_as_review_work() {
    let mut inputs = base_inputs();
    inputs.base_url = Some("http://127.0.0.1:4010".to_owned());
    inputs.request_mappings = vec![RequestMapping {
        selector: SelectorReference {
            role: "subject".to_owned(),
            profile: "subject-reference-v1".to_owned(),
            field: "reference".to_owned(),
            scalar_type: SelectorScalarType::String,
            maximum_bytes: 128,
        },
        target: RequestTarget::Query("reference".to_owned()),
    }];

    let artifacts = emit::draft(&inputs).expect("mapped draft");
    let source: serde_json::Value =
        serde_json::from_str(&artifacts.authoring_source).expect("normalized Source JSON");
    let prepare = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-prepare.rhai",
    );
    let pack: serde_json::Value = serde_norway::from_str(file_contents(
        &artifacts,
        "adapter-packs/search-a/pack.yaml",
    ))
    .expect("AdapterPack YAML");

    assert_eq!(
        source["inputs"],
        json!({"input1":{"selector":{
            "role":"subject","profile":"subject-reference-v1","field":"reference"
        }}})
    );
    assert_eq!(
        to_parameters(&pack)["query"]["reference"]["jsonpath"],
        "$.input1"
    );
    assert!(!prepare.contains("TODO(evidencectl)"), "{prepare}");

    assert!(
        artifacts
            .report
            .contains("Review the generated selector bindings and pack request mapping."),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("Configure target-owned authentication."),
        "{}",
        artifacts.report
    );
    assert!(
        artifacts
            .report
            .contains("Review the generated Source posture and default source limits."),
        "{}",
        artifacts.report
    );
    assert!(
        !artifacts.report.contains("source origin"),
        "{}",
        artifacts.report
    );
    assert!(
        !artifacts.report.contains("intentionally absent"),
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

    let expected = "evidencectl source suggest /tmp/example-project \
--operation 'GET /v1/records' \
--status 200 \
--media-type application/json \
--sample tests/fixtures/samples/example.json \
--source-id search-a \
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

/// Verify a freshly written stub under the shared test-only ETXTBSY bound.
#[cfg(unix)]
fn verify_stub(project: &Path, stub: &Path) -> CheckClassification {
    evidence_binary::retry_busy_stub(|| emit::verify(project, Some(stub)))
        .unwrap_or_else(|error| panic!("verify: {error:#}"))
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

    let error = match evidence_binary::retry_busy_stub(|| emit::verify(&project, Some(&stub))) {
        Ok(classification) => panic!("a foreign runtime was trusted: {classification:?}"),
        Err(error) => error,
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
    inputs.narrowed = NarrowOutcome {
        schema: json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{
                "say\"hi":{"type":"string","maxLength":64},
                "back\\slash":{"type":"string","maxLength":64}
            }
        }),
        unresolved: Vec::new(),
    };
    inputs.needs = Vec::new();
    let artifacts = emit::draft(&inputs).expect("draft");
    let extract = file_contents(
        &artifacts,
        "adapter-packs/search-a/scripts/search-a-extract.rhai",
    );

    assert!(
        extract.contains(r#"if "say\"hi" in value"#),
        "a double quote must be escaped in the Rhai literal:\n{extract}"
    );
    assert!(
        extract.contains(r#"if "back\\slash" in value"#),
        "a backslash must be escaped in the Rhai literal:\n{extract}"
    );
    assert!(!extract.contains("get_path"), "{extract}");
}

/// The same applies to the drafted YAML: a double-quoted scalar carrying a raw
/// newline or tab folds, silently changing the value the runtime reads.
#[test]
fn drafted_yaml_escapes_control_characters_in_a_scalar() {
    let mut inputs = base_inputs();
    inputs.media_type = "application/json\nx-injected: true".to_owned();
    let artifacts = emit::draft(&inputs).expect("draft");
    let pack_text = file_contents(&artifacts, "adapter-packs/search-a/pack.yaml");
    let parsed: serde_json::Value = serde_norway::from_str(pack_text).unwrap();
    let accept = parsed["sourceRoutes"][0]["steps"]
        .as_array()
        .expect("route steps")
        .iter()
        .find_map(|step| step.get("setHeader"))
        .expect("static Accept header");
    assert_eq!(
        accept["value"]["constant"].as_str(),
        Some("application/json\nx-injected: true"),
        "the scalar must round-trip without becoming a sibling key:\n{pack_text}"
    );
    assert_eq!(accept["name"], "Accept");
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

    assert!(all.contains("scripts/search-a-prepare.rhai"));
    assert!(all.contains("scripts/search-a-extract.rhai"));
    assert!(artifacts.files.iter().all(|file| file
        .bundle_relative_path
        .starts_with("adapter-packs/search-a/")));
    assert!(!all.contains("schemas/search-a-response.schema.yaml"));
    assert!(!all.contains("adapters/search-a-extract.rhai"));
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
    let response_schema = file_contents(
        &artifacts,
        "adapter-packs/search-a/schemas/search-a-facts.schema.json",
    );

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(response_schema).unwrap()["type"].as_str(),
        Some("array")
    );
    assert!(artifacts.report.contains("response root"));
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
    let script = "#!/bin/sh\nprintf 'evidence: runtime audit initialization failed: the audit hash key is unusable\\n' >&2\nexit 1\n";
    let stub = write_stub_evidence(temp.path(), script);
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("mkdir project");

    let classification = verify_stub(&project, &stub);
    assert_eq!(classification, CheckClassification::SecretsUnprovisioned);
}
