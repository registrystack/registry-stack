//! `evidencectl source suggest` end to end, through the real binary.
//!
//! Every case here drives the installed `evidencectl` executable
//! non-interactively, the way an operator reproduces a reviewed interactive
//! run: a synthetic OpenAPI document and a synthetic sample response are
//! written into a temporary directory, and the command is asked to draft one
//! source from them. Nothing here reaches the network, and no sample value is
//! expected in any assertion: only bounds derived from the sample are.
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

/// A two-operation document with one paginated collection response. The
/// vocabulary is deliberately generic: records, trackingId, status, total,
/// recordedOn.
const OPENAPI_DOCUMENT: &str = r#"openapi: 3.0.3
info:
  title: Example record service
  version: "1.0.0"
servers:
  - url: https://records.example.invalid/v1
paths:
  /records:
    get:
      summary: List records
      parameters:
        - name: pageSize
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 50
      responses:
        "200":
          description: matching records
          content:
            application/json:
              schema:
                type: object
                required: [total, records]
                properties:
                  total:
                    type: integer
                  records:
                    type: array
                    items:
                      $ref: '#/components/schemas/Record'
components:
  schemas:
    Record:
      type: object
      required: [trackingId]
      properties:
        trackingId:
          type: string
        status:
          type: string
          enum: [active, closed]
        recordedOn:
          type: string
          format: date
        tags:
          type: array
          items:
            type: string
            maxLength: 32
"#;

/// Two records, so the array observation is a real length rather than one.
const SAMPLE_RESPONSE: &str = r#"{
  "total": 3,
  "records": [
    {"trackingId": "TR-000001", "status": "active", "recordedOn": "2024-05-01"},
    {"trackingId": "TR-000002", "status": "closed", "recordedOn": "2024-05-02"}
  ]
}
"#;

const MAPPED_GET_OPENAPI: &str = r#"openapi: 3.1.0
info:
  title: Mapped record service
  version: "1.0.0"
paths:
  /records/{record_id}:
    get:
      parameters:
        - name: record_id
          in: path
          required: true
          schema: {type: string}
        - name: reference
          in: query
          required: true
          schema: {type: string}
      responses:
        "200":
          description: record
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                required: [allowed]
                properties:
                  allowed: {type: boolean}
"#;

#[test]
fn explicit_selector_mappings_generate_path_bindings_and_query_preparation() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), MAPPED_GET_OPENAPI);
    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--operation".to_owned(),
        "GET /records/{record_id}".to_owned(),
        "--select".to_owned(),
        "/allowed".to_owned(),
        "--source-id".to_owned(),
        "mapped".to_owned(),
        "--map-selector".to_owned(),
        "subject.subject-reference-v1.reference=path:record_id".to_owned(),
        "--map-selector".to_owned(),
        "subject.subject-reference-v1.reference=query:reference".to_owned(),
        path_argument(&project),
    ]);
    assert!(
        output.status.success(),
        "source suggest failed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains("selector bindings, preparation")
            && !stdout.contains("request limits are intentionally absent"),
        "the report must not describe generated request machinery as absent: {stdout}"
    );

    let document: Value = serde_norway::from_str(
        &std::fs::read_to_string(project.join("evidence.yaml")).expect("read project"),
    )
    .expect("parse project");
    let source = &document["sources"]["mapped"];
    assert_eq!(
        source["selectors"],
        serde_json::json!([{"role":"subject","profiles":["subject-reference-v1"]}])
    );
    assert_eq!(
        source["request"]["pathBindings"]["record_id"]["selector"]["field"],
        "reference"
    );
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("read prepare Function");
    assert!(prepare.contains(r#"query_pair("reference""#), "{prepare}");
    assert!(!prepare.contains("TODO(evidencectl)"), "{prepare}");
}

#[test]
fn mapped_get_and_post_projects_pass_the_offline_compiler() {
    let post = request_openapi(
        "POST",
        "/records/{record_id}",
        vec![
            parameter("record_id", "path", true, "string"),
            parameter("reference", "query", true, "string"),
        ],
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["reference"],
                "properties":{"reference":{"type":"string"}}
            }),
        )),
    );
    for (method, document, body_requirement) in [
        ("GET", MAPPED_GET_OPENAPI, "forbidden"),
        ("POST", post.as_str(), "required"),
    ] {
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), document);
        let mut mappings = vec![
            "subject.subject-reference-v1.reference=path:record_id".to_owned(),
            "subject.subject-reference-v1.reference=query:reference".to_owned(),
        ];
        if method == "POST" {
            mappings.push("subject.subject-reference-v1.reference=body:/reference".to_owned());
        }
        let generated = mapped_suggest(&project, &mappings);
        assert!(
            generated.status.success(),
            "{method} generation: {}",
            stderr_of(&generated)
        );

        let checked = evidencectl(&[
            "--format".to_owned(),
            "json".to_owned(),
            "check".to_owned(),
            path_argument(&project),
        ]);
        assert!(
            checked.status.success(),
            "{method} check: {}{}",
            stdout_of(&checked),
            stderr_of(&checked)
        );
        assert!(stderr_of(&checked).is_empty());
        let report: Value = serde_json::from_slice(&checked.stdout).expect("check JSON report");
        assert_eq!(report["proof"], "authoring");
        assert_eq!(report["networkAccess"], false);
        let source = report["sources"]
            .as_array()
            .expect("checked Sources")
            .iter()
            .find(|source| source["id"] == "mapped")
            .expect("generated Source was compiled");
        assert_eq!(source["operation"]["method"], method);
        assert_eq!(source["operation"]["path"], "/records/{record_id}");
        assert_eq!(source["resolvedPreparation"]["generated"], false);
        assert_eq!(
            source["resolvedPreparation"]["script"],
            "adapters/functions/mapped-prepare.rhai"
        );
        let limits = &source["resolvedPreparation"]["limits"];
        assert_eq!(limits["query"], "required");
        assert_eq!(limits["maximumQueryPairs"], 1);
        assert_eq!(limits["jsonBody"], body_requirement);
    }
}

#[test]
fn unsupported_path_placeholders_are_refused_without_mutation() {
    for name in [
        "RecordId".to_owned(),
        "1record".to_owned(),
        "record.id".to_owned(),
        "récord".to_owned(),
        "r".repeat(65),
    ] {
        let document = request_openapi(
            "GET",
            &format!("/records/{{{name}}}"),
            vec![parameter(&name, "path", true, "string")],
            None,
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        assert_mapping_failure_is_atomic(
            &project,
            &[format!(
                "subject.subject-reference-v1.reference=path:{name}"
            )],
            if name.is_ascii() {
                "must be a Registry Stack LocalId"
            } else {
                "absolute ASCII paths"
            },
            &format!("unsupported path placeholder {name}"),
        );
    }
    for (path, parameters, mapping, expected) in [
        (
            "/records/{record_id}/{record_id}",
            vec![parameter("record_id", "path", true, "string")],
            "subject.subject-reference-v1.reference=path:record_id",
            "path placeholders must be unique",
        ),
        (
            "/records/{missing}",
            vec![parameter("reference", "query", true, "string")],
            "subject.subject-reference-v1.reference=query:reference",
            "path:missing",
        ),
        (
            "/records/prefix-{record_id}",
            vec![parameter("reference", "query", true, "string")],
            "subject.subject-reference-v1.reference=query:reference",
            "path placeholder must occupy one complete segment",
        ),
    ] {
        let document = request_openapi("GET", path, parameters, None);
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        assert_mapping_failure_is_atomic(&project, &[mapping.to_owned()], expected, path);
    }
}

#[test]
fn invalid_rendered_request_paths_are_refused_without_mutation() {
    for path in [
        "/records/{record_id}/".to_owned(),
        "//records/{record_id}".to_owned(),
        "/records//{record_id}".to_owned(),
        "/records/./{record_id}".to_owned(),
        "/records/../{record_id}".to_owned(),
        "/récords/{record_id}".to_owned(),
        "/records?fixed=1/{record_id}".to_owned(),
        "/records#fragment/{record_id}".to_owned(),
        "/records\\other/{record_id}".to_owned(),
        "/records/%2e/{record_id}".to_owned(),
        "/records/%2F/{record_id}".to_owned(),
        "/records/%41/{record_id}".to_owned(),
        "/records/%GG/{record_id}".to_owned(),
        format!("/{}/{{record_id}}", "a".repeat(2048)),
    ] {
        let document = request_openapi(
            "GET",
            &path,
            vec![parameter("record_id", "path", true, "string")],
            None,
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        assert_mapping_failure_is_atomic(
            &project,
            &["subject.subject-reference-v1.reference=path:record_id".to_owned()],
            "generated request path",
            &path,
        );
    }
}

#[test]
fn invalid_rendered_server_prefixes_are_refused_without_mutation() {
    for prefix in [
        "/api//v1".to_owned(),
        "/api/./v1".to_owned(),
        "/api/../v1".to_owned(),
        "/api/%2F".to_owned(),
        "/api/%2e".to_owned(),
        format!("/{}", "a".repeat(2040)),
    ] {
        let mut document: Value = serde_norway::from_str(MAPPED_GET_OPENAPI).expect("OpenAPI");
        document["servers"] =
            serde_json::json!([{"url":format!("https://records.example.invalid{prefix}")}]);
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(
            workspace.path(),
            &serde_norway::to_string(&document).expect("OpenAPI YAML"),
        );
        assert_mapping_failure_is_atomic(
            &project,
            &[
                "subject.subject-reference-v1.reference=path:record_id".to_owned(),
                "subject.subject-reference-v1.reference=query:reference".to_owned(),
            ],
            "generated request path",
            &prefix,
        );
    }
}

#[test]
fn invalid_selector_mappings_refuse_before_mutating_the_project() {
    struct Case {
        name: &'static str,
        document: String,
        mappings: Vec<String>,
        add_alternate_field: bool,
        expected: &'static str,
    }

    let string_query = request_openapi(
        "GET",
        "/records",
        vec![parameter("reference", "query", true, "string")],
        None,
    );
    let integer_query = request_openapi(
        "GET",
        "/records",
        vec![parameter("reference", "query", true, "integer")],
        None,
    );
    let mut short_string_parameter = parameter("reference", "query", true, "string");
    short_string_parameter["schema"]["maxLength"] = serde_json::json!(8);
    let short_string_query = request_openapi("GET", "/records", vec![short_string_parameter], None);
    let mut bounded_integer_parameter = parameter("value", "query", true, "integer");
    bounded_integer_parameter["schema"]["minimum"] = serde_json::json!(0);
    bounded_integer_parameter["schema"]["maximum"] = serde_json::json!(10);
    let bounded_integer_query =
        request_openapi("GET", "/records", vec![bounded_integer_parameter], None);
    let mut patterned_parameter = parameter("reference", "query", true, "string");
    patterned_parameter["schema"]["pattern"] = serde_json::json!("^[A-Z]+$");
    let patterned_query = request_openapi("GET", "/records", vec![patterned_parameter], None);
    let mut negated_parameter = parameter("reference", "query", true, "string");
    negated_parameter["schema"]["not"] = serde_json::json!({"const":"forbidden"});
    let negated_query = request_openapi("GET", "/records", vec![negated_parameter], None);
    let mut dynamic_parameter = parameter("reference", "query", true, "string");
    dynamic_parameter["schema"]["$dynamicRef"] = serde_json::json!("#restricted");
    let dynamic_query = request_openapi("GET", "/records", vec![dynamic_parameter], None);
    let recursive_object_body = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "$recursiveRef":"#restricted",
                "required":["reference"],
                "properties":{"reference":{"type":"string"}}
            }),
        )),
    );
    let required_header = request_openapi(
        "GET",
        "/records",
        vec![
            parameter("reference", "query", true, "string"),
            parameter("X-Required", "header", true, "string"),
        ],
        None,
    );
    let required_cookie = request_openapi(
        "GET",
        "/records",
        vec![
            parameter("reference", "query", true, "string"),
            parameter("session", "cookie", true, "string"),
        ],
        None,
    );
    let required_path_and_query = request_openapi(
        "GET",
        "/records/{record_id}",
        vec![
            parameter("record_id", "path", true, "string"),
            parameter("reference", "query", true, "string"),
        ],
        None,
    );
    let mut matrix_path_parameter = parameter("record_id", "path", true, "string");
    matrix_path_parameter["style"] = serde_json::json!("matrix");
    matrix_path_parameter["explode"] = serde_json::json!(false);
    let matrix_path = request_openapi(
        "GET",
        "/records/{record_id}",
        vec![matrix_path_parameter],
        None,
    );
    let mut deep_object_query_parameter = parameter("reference", "query", true, "string");
    deep_object_query_parameter["style"] = serde_json::json!("deepObject");
    deep_object_query_parameter["explode"] = serde_json::json!(true);
    let deep_object_query =
        request_openapi("GET", "/records", vec![deep_object_query_parameter], None);
    let array_body = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["values"],
                "properties":{"values":{"type":"array","items":{"type":"string"}}}
            }),
        )),
    );
    let open_body = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":true,
                "required":["reference"],
                "properties":{"reference":{"type":"string"}}
            }),
        )),
    );
    let constrained_object_body = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false, "minProperties":2,
                "required":["reference"],
                "properties":{"reference":{"type":"string"}}
            }),
        )),
    );
    let optional_body = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            false,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["required_value"],
                "properties":{
                    "required_value":{"type":"string"},
                    "optional_value":{"type":"string"}
                }
            }),
        )),
    );
    let required_empty_object = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["reference","criteria"],
                "properties":{
                    "reference":{"type":"string"},
                    "criteria":{"type":"object","additionalProperties":false,"properties":{}}
                }
            }),
        )),
    );
    let cases = vec![
        Case {
            name: "unknown role",
            document: string_query.clone(),
            mappings: vec!["other.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "unknown subject role",
        },
        Case {
            name: "unknown profile",
            document: string_query.clone(),
            mappings: vec!["subject.other-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "unknown selector profile",
        },
        Case {
            name: "unknown field",
            document: string_query.clone(),
            mappings: vec!["subject.subject-reference-v1.other=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "has no field",
        },
        Case {
            name: "incompatible type",
            document: integer_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "does not declare that scalar type",
        },
        Case {
            name: "string domain wider than maxLength",
            document: short_string_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "byte bounds cannot prove",
        },
        Case {
            name: "integer domain wider than maximum",
            document: bounded_integer_query,
            mappings: vec!["subject.integer-v1.value=query:value".to_owned()],
            add_alternate_field: false,
            expected: "integer range is wider",
        },
        Case {
            name: "pattern cannot be proven",
            document: patterned_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "cannot be proven compatible",
        },
        Case {
            name: "negated scalar schema cannot be proven",
            document: negated_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "declares `not`",
        },
        Case {
            name: "dynamic scalar reference is unsupported",
            document: dynamic_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "declares `$dynamicRef`",
        },
        Case {
            name: "recursive object reference is unsupported",
            document: recursive_object_body,
            mappings: vec!["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            add_alternate_field: false,
            expected: "unsupported object constraint `$recursiveRef`",
        },
        Case {
            name: "duplicate target",
            document: string_query.clone(),
            mappings: vec![
                "subject.subject-reference-v1.reference=query:reference".to_owned(),
                "subject.subject-reference-v1.alternate=query:reference".to_owned(),
            ],
            add_alternate_field: true,
            expected: "assigned more than once",
        },
        Case {
            name: "missing required query",
            document: required_path_and_query,
            mappings: vec!["subject.subject-reference-v1.reference=path:record_id".to_owned()],
            add_alternate_field: false,
            expected: "required request input `query:reference`",
        },
        Case {
            name: "matrix path serialization",
            document: matrix_path,
            mappings: vec!["subject.subject-reference-v1.reference=path:record_id".to_owned()],
            add_alternate_field: false,
            expected: "unsupported OpenAPI serialization",
        },
        Case {
            name: "deep-object query serialization",
            document: deep_object_query,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "unsupported OpenAPI serialization",
        },
        Case {
            name: "required header",
            document: required_header,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "cannot set headers or cookies",
        },
        Case {
            name: "required cookie",
            document: required_cookie,
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            add_alternate_field: false,
            expected: "cannot set headers or cookies",
        },
        Case {
            name: "array body",
            document: array_body,
            mappings: vec!["subject.subject-reference-v1.reference=body:/values".to_owned()],
            add_alternate_field: false,
            expected: "must name one scalar",
        },
        Case {
            name: "open body",
            document: open_body,
            mappings: vec!["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            add_alternate_field: false,
            expected: "simple closed object schema",
        },
        Case {
            name: "constrained body object",
            document: constrained_object_body,
            mappings: vec!["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            add_alternate_field: false,
            expected: "unsupported object constraint `minProperties`",
        },
        Case {
            name: "optional body becomes present",
            document: optional_body,
            mappings: vec![
                "subject.subject-reference-v1.reference=body:/optional_value".to_owned(),
            ],
            add_alternate_field: false,
            expected: "body:/required_value",
        },
        Case {
            name: "required empty object",
            document: required_empty_object,
            mappings: vec!["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            add_alternate_field: false,
            expected: "no required scalar leaves",
        },
    ];

    for case in cases {
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &case.document);
        if case.add_alternate_field {
            add_string_selector_field(&project, "alternate", 128);
        }
        assert_mapping_failure_is_atomic(&project, &case.mappings, case.expected, case.name);
    }
}

#[test]
fn optional_request_body_may_remain_absent_when_only_query_is_mapped() {
    let document = request_openapi(
        "POST",
        "/records",
        vec![parameter("reference", "query", true, "string")],
        Some(json_body(
            false,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["required_value"],
                "properties":{"required_value":{"type":"string"}}
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(prepare.contains("body: ()"), "{prepare}");
}

#[test]
fn optional_non_json_request_body_may_remain_unused_by_query_mapping() {
    let document = request_openapi(
        "POST",
        "/records",
        vec![parameter("reference", "query", true, "string")],
        Some(form_body(false)),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(prepare.contains("body: ()"), "{prepare}");
}

#[test]
fn unused_optional_content_parameters_do_not_block_query_mapping() {
    let document = request_openapi(
        "GET",
        "/records",
        vec![
            parameter("reference", "query", true, "string"),
            content_parameter("X-Trace", "header", false),
            content_parameter("session", "cookie", false),
        ],
        None,
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
}

#[test]
fn unused_optional_external_parameter_does_not_block_query_mapping() {
    let document = request_openapi(
        "GET",
        "/records",
        vec![
            parameter("reference", "query", true, "string"),
            external_schema_parameter("optional_filter", "query", false),
        ],
        None,
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
}

#[test]
fn unused_optional_json_body_with_external_schema_does_not_block_query_mapping() {
    let document = request_openapi(
        "POST",
        "/records",
        vec![parameter("reference", "query", true, "string")],
        Some(external_json_body(false)),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(prepare.contains("body: ()"), "{prepare}");
}

#[test]
fn required_or_selected_unsupported_inputs_are_refused_without_mutation() {
    struct Case {
        name: &'static str,
        document: String,
        mappings: Vec<String>,
        expected: &'static str,
    }

    let cases = [
        Case {
            name: "required content-based header",
            document: request_openapi(
                "GET",
                "/records",
                vec![
                    parameter("reference", "query", true, "string"),
                    content_parameter("X-Required", "header", true),
                ],
                None,
            ),
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            expected: "content-based parameters are not supported",
        },
        Case {
            name: "required content-based cookie",
            document: request_openapi(
                "GET",
                "/records",
                vec![
                    parameter("reference", "query", true, "string"),
                    content_parameter("session", "cookie", true),
                ],
                None,
            ),
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            expected: "content-based parameters are not supported",
        },
        Case {
            name: "required external query schema",
            document: request_openapi(
                "GET",
                "/records",
                vec![external_schema_parameter("reference", "query", true)],
                None,
            ),
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            expected: "external or remote $ref",
        },
        Case {
            name: "selected optional external query schema",
            document: request_openapi(
                "GET",
                "/records",
                vec![external_schema_parameter("reference", "query", false)],
                None,
            ),
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            expected: "external or remote $ref",
        },
        Case {
            name: "required JSON body with external schema",
            document: request_openapi(
                "POST",
                "/records",
                vec![parameter("reference", "query", true, "string")],
                Some(external_json_body(true)),
            ),
            mappings: vec!["subject.subject-reference-v1.reference=query:reference".to_owned()],
            expected: "external or remote $ref",
        },
        Case {
            name: "selected optional JSON body with external schema",
            document: request_openapi(
                "POST",
                "/records",
                Vec::new(),
                Some(external_json_body(false)),
            ),
            mappings: vec!["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            expected: "external or remote $ref",
        },
    ];

    for case in cases {
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &case.document);
        assert_mapping_failure_is_atomic(&project, &case.mappings, case.expected, case.name);
    }
}

#[test]
fn operation_override_is_applied_before_unused_input_selection() {
    let document = request_openapi_with_path_parameters(
        "GET",
        "/records",
        vec![external_schema_parameter("shadowed", "query", true)],
        vec![
            parameter("shadowed", "query", false, "string"),
            parameter("reference", "query", true, "string"),
        ],
        None,
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
}

#[test]
fn unproven_scalar_constraints_are_refused_without_mutation() {
    for (keyword, constraint) in [
        ("enum", serde_json::json!(["reviewed-value"])),
        ("const", serde_json::json!("reviewed-value")),
        ("readOnly", serde_json::json!(true)),
        ("format", serde_json::json!("email")),
    ] {
        let mut scalar = serde_json::json!({"type": "string"});
        scalar[keyword] = constraint;
        let document = request_openapi(
            "POST",
            "/records",
            Vec::new(),
            Some(json_body(
                true,
                serde_json::json!({
                    "type": "object", "additionalProperties": false,
                    "required": ["reference"],
                    "properties": {"reference": scalar}
                }),
            )),
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        assert_mapping_failure_is_atomic(
            &project,
            &["subject.subject-reference-v1.reference=body:/reference".to_owned()],
            keyword,
            &format!("unproven scalar {keyword}"),
        );
    }
}

#[test]
fn materialized_object_constraints_are_refused_without_mutation() {
    let constrained_root = |keyword: &str, constraint: Value| {
        let mut schema = serde_json::json!({
            "type":"object", "additionalProperties":false,
            "required":["reference"],
            "properties":{"reference":{"type":"string"}}
        });
        schema[keyword] = constraint;
        request_openapi(
            "POST",
            "/records",
            Vec::new(),
            Some(json_body(true, schema)),
        )
    };
    let read_only_ancestor = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "properties":{
                    "criteria":{
                        "type":"object", "additionalProperties":false, "readOnly":true,
                        "required":["reference"],
                        "properties":{"reference":{"type":"string"}}
                    }
                }
            }),
        )),
    );
    let cases = [
        (
            "object enum",
            constrained_root("enum", serde_json::json!([{"reference":"reviewed-value"}])),
            "body:/reference",
            "unsupported object constraint `enum`",
        ),
        (
            "object const",
            constrained_root("const", serde_json::json!({"reference":"reviewed-value"})),
            "body:/reference",
            "unsupported object constraint `const`",
        ),
        (
            "read-only object ancestor",
            read_only_ancestor,
            "body:/criteria/reference",
            "readOnly",
        ),
    ];

    for (name, document, target, expected) in cases {
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        assert_mapping_failure_is_atomic(
            &project,
            &[format!("subject.subject-reference-v1.reference={target}")],
            expected,
            name,
        );
    }
}

#[test]
fn incompatible_or_unknown_integer_formats_are_refused_without_mutation() {
    let cases = [
        (
            "int32 selector domain is too wide",
            serde_json::json!("int32"),
            0_i64,
            3_000_000_000_i64,
            "int32",
        ),
        (
            "unknown integer format",
            serde_json::json!("uint64"),
            0,
            100,
            "unsupported integer format",
        ),
        (
            "malformed integer format",
            serde_json::json!(32),
            0,
            100,
            "unsupported integer format",
        ),
    ];
    for (name, format, minimum, maximum, expected) in cases {
        let mut value = parameter("value", "query", true, "integer");
        value["schema"]["format"] = format;
        let document = request_openapi("GET", "/records", vec![value], None);
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        set_integer_selector_bounds(&project, minimum, maximum);
        assert_mapping_failure_is_atomic(
            &project,
            &["subject.integer-v1.value=query:value".to_owned()],
            expected,
            name,
        );
    }
}

#[test]
fn supported_integer_formats_accept_the_full_declared_domain() {
    let cases = [
        (Some("int32"), i32::MIN as i64, i32::MAX as i64),
        (
            Some("int64"),
            -9_007_199_254_740_991_i64,
            9_007_199_254_740_991_i64,
        ),
        (None, -9_007_199_254_740_991_i64, 9_007_199_254_740_991_i64),
    ];
    for (format, minimum, maximum) in cases {
        let mut value = parameter("value", "query", true, "integer");
        if let Some(format) = format {
            value["schema"]["format"] = serde_json::json!(format);
        }
        let document = request_openapi("GET", "/records", vec![value], None);
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        set_integer_selector_bounds(&project, minimum, maximum);
        let output = mapped_suggest(
            &project,
            &["subject.integer-v1.value=query:value".to_owned()],
        );
        assert!(
            output.status.success(),
            "format {format:?} with {minimum}..={maximum}: {}",
            stderr_of(&output)
        );
    }
}

#[test]
fn required_non_json_request_body_is_refused_without_mutation() {
    let document = request_openapi(
        "POST",
        "/records",
        vec![parameter("reference", "query", true, "string")],
        Some(form_body(true)),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    assert_mapping_failure_is_atomic(
        &project,
        &["subject.subject-reference-v1.reference=query:reference".to_owned()],
        "has no `application/json` content",
        "required non-JSON body",
    );
}

#[test]
fn explicit_mapping_to_optional_non_json_body_is_refused_without_mutation() {
    let document = request_openapi("POST", "/records", Vec::new(), Some(form_body(false)));
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    assert_mapping_failure_is_atomic(
        &project,
        &["subject.subject-reference-v1.reference=body:/reference".to_owned()],
        "has no `application/json` content",
        "explicit mapping to an optional non-JSON body",
    );
}

#[test]
fn mapped_optional_object_requires_its_required_sibling_without_mutation() {
    let document = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["request_id"],
                "properties":{
                    "request_id":{"type":"string"},
                    "criteria":{
                        "type":"object", "additionalProperties":false,
                        "required":["reference","required_sibling"],
                        "properties":{
                            "reference":{"type":"string"},
                            "required_sibling":{"type":"string"}
                        }
                    }
                }
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    assert_mapping_failure_is_atomic(
        &project,
        &[
            "subject.subject-reference-v1.reference=body:/request_id".to_owned(),
            "subject.subject-reference-v1.reference=body:/criteria/reference".to_owned(),
        ],
        "required request input `body:/criteria/required_sibling`",
        "mapped optional object with an omitted required sibling",
    );
}

#[test]
fn mapped_deep_optional_object_requires_its_required_sibling_without_mutation() {
    let document = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["request_id"],
                "properties":{
                    "request_id":{"type":"string"},
                    "envelope":{
                        "type":"object", "additionalProperties":false,
                        "properties":{
                            "criteria":{
                                "type":"object", "additionalProperties":false,
                                "required":["reference","required_sibling"],
                                "properties":{
                                    "reference":{"type":"string"},
                                    "required_sibling":{"type":"string"}
                                }
                            }
                        }
                    }
                }
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    assert_mapping_failure_is_atomic(
        &project,
        &[
            "subject.subject-reference-v1.reference=body:/request_id".to_owned(),
            "subject.subject-reference-v1.reference=body:/envelope/criteria/reference".to_owned(),
        ],
        "required request input `body:/envelope/criteria/required_sibling`",
        "mapped object below two optional ancestors with an omitted required sibling",
    );
}

#[test]
fn complete_optional_object_materialization_succeeds() {
    let document = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["request_id"],
                "properties":{
                    "request_id":{"type":"string"},
                    "criteria":{
                        "type":"object", "additionalProperties":false,
                        "required":["reference","required_sibling"],
                        "properties":{
                            "reference":{"type":"string"},
                            "required_sibling":{"type":"string"}
                        }
                    }
                }
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &[
            "subject.subject-reference-v1.reference=body:/request_id".to_owned(),
            "subject.subject-reference-v1.reference=body:/criteria/reference".to_owned(),
            "subject.subject-reference-v1.reference=body:/criteria/required_sibling".to_owned(),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(prepare.contains(r#""criteria": #{"#), "{prepare}");
    assert!(prepare.contains(r#""required_sibling":"#), "{prepare}");
}

#[test]
fn fully_required_nested_object_with_shared_mapped_leaves_succeeds() {
    let document = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["outer"],
                "properties":{
                    "outer":{
                        "type":"object", "additionalProperties":false,
                        "required":["inner"],
                        "properties":{
                            "inner":{
                                "type":"object", "additionalProperties":false,
                                "required":["reference","required_sibling"],
                                "properties":{
                                    "reference":{"type":"string"},
                                    "required_sibling":{"type":"string"}
                                }
                            }
                        }
                    }
                }
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &[
            "subject.subject-reference-v1.reference=body:/outer/inner/reference".to_owned(),
            "subject.subject-reference-v1.reference=body:/outer/inner/required_sibling".to_owned(),
        ],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(prepare.contains(r#""outer": #{"#), "{prepare}");
    assert!(prepare.contains(r#""inner": #{"#), "{prepare}");
}

#[test]
fn wholly_absent_optional_object_stays_omitted() {
    let document = request_openapi(
        "POST",
        "/records",
        Vec::new(),
        Some(json_body(
            true,
            serde_json::json!({
                "type":"object", "additionalProperties":false,
                "required":["request_id"],
                "properties":{
                    "request_id":{"type":"string"},
                    "criteria":{
                        "type":"object", "additionalProperties":false,
                        "required":["reference","required_sibling"],
                        "properties":{
                            "reference":{"type":"string"},
                            "required_sibling":{"type":"string"}
                        }
                    }
                }
            }),
        )),
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    let output = mapped_suggest(
        &project,
        &["subject.subject-reference-v1.reference=body:/request_id".to_owned()],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let prepare = std::fs::read_to_string(project.join("functions/mapped-prepare.rhai"))
        .expect("generated prepare Function");
    assert!(!prepare.contains(r#""criteria""#), "{prepare}");
}

#[test]
fn request_mapping_runtime_bounds_accept_the_limit_and_refuse_one_past_it() {
    for (count, succeeds) in [(64_usize, true), (65, false)] {
        let parameters = (0..count)
            .map(|index| parameter(&format!("q{index}"), "query", true, "string"))
            .collect();
        let document = request_openapi("GET", "/records", parameters, None);
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        let mappings = (0..count)
            .map(|index| format!("subject.subject-reference-v1.reference=query:q{index}"))
            .collect::<Vec<_>>();
        let before = project_snapshot(&project);
        let output = mapped_suggest(&project, &mappings);
        assert_eq!(output.status.success(), succeeds, "{}", stderr_of(&output));
        if !succeeds {
            assert!(stderr_of(&output).contains("64-pair"));
            assert_eq!(project_snapshot(&project), before);
        }
    }

    for (name_bytes, succeeds) in [(64_usize, true), (65, false)] {
        let name = "q".repeat(name_bytes);
        let document = request_openapi(
            "GET",
            "/records",
            vec![parameter(&name, "query", true, "string")],
            None,
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        let output = mapped_suggest(
            &project,
            &[format!(
                "subject.subject-reference-v1.reference=query:{name}"
            )],
        );
        assert_eq!(output.status.success(), succeeds, "{}", stderr_of(&output));
    }

    for (maximum_bytes, succeeds) in [(4096_u64, true), (4097, false)] {
        let document = request_openapi(
            "GET",
            "/records",
            vec![parameter("reference", "query", true, "string")],
            None,
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        set_reference_selector_maximum(&project, maximum_bytes);
        let output = mapped_suggest(
            &project,
            &["subject.subject-reference-v1.reference=query:reference".to_owned()],
        );
        assert_eq!(output.status.success(), succeeds, "{}", stderr_of(&output));
    }

    let document = request_openapi(
        "GET",
        "/records",
        (0..3)
            .map(|index| parameter(&format!("q{index}"), "query", true, "string"))
            .collect(),
        None,
    );
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), &document);
    set_reference_selector_maximum(&project, 4096);
    assert_mapping_failure_is_atomic(
        &project,
        &(0..3)
            .map(|index| format!("subject.subject-reference-v1.reference=query:q{index}"))
            .collect::<Vec<_>>(),
        "normalized bytes",
        "worst-case escaped query values",
    );

    for (key_bytes, succeeds) in [(16_384_usize, true), (16_385, false)] {
        let key = "k".repeat(key_bytes);
        let mut properties = serde_json::Map::new();
        properties.insert(key.clone(), serde_json::json!({"type":"string"}));
        let document = request_openapi(
            "POST",
            "/records",
            Vec::new(),
            Some(json_body(
                true,
                serde_json::json!({
                    "type":"object", "additionalProperties":false,
                    "required":[&key], "properties":properties
                }),
            )),
        );
        let workspace = tempfile::tempdir().expect("tempdir");
        let project = scaffold(workspace.path(), &document);
        let output = mapped_suggest(
            &project,
            &[format!(
                "subject.subject-reference-v1.reference=body:/{key}"
            )],
        );
        assert_eq!(output.status.success(), succeeds, "{}", stderr_of(&output));
    }
}

#[test]
fn drafts_into_a_project_and_then_refuses_to_overwrite_the_draft() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let sample = write(workspace.path(), "records.sample.json", SAMPLE_RESPONSE);
    let project = scaffold(workspace.path(), OPENAPI_DOCUMENT);

    let arguments = vec![
        "source".to_owned(),
        "suggest".to_owned(),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/total".to_owned(),
        "--select".to_owned(),
        "/records/*/trackingId".to_owned(),
        "--sample".to_owned(),
        path_argument(&sample),
        "--source-id".to_owned(),
        "source-b".to_owned(),
        path_argument(&project),
    ];
    let output = evidencectl(&arguments);
    assert!(
        output.status.success(),
        "source suggest failed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(stdout.contains(&project.join("evidence.yaml").display().to_string()));
    assert!(!stdout.contains("sources/source-b.yaml"), "{stdout}");
    assert!(stdout.contains("evidencectl check"), "{stdout}");
    assert!(stdout.contains("authored fixtures"), "{stdout}");
    assert!(stdout.contains("evidencectl test"), "{stdout}");

    let prepare_path = project.join("functions/source-b-prepare.rhai");
    let script_path = project.join("functions/source-b-extract.rhai");
    for path in [&prepare_path, &script_path, &project.join("evidence.yaml")] {
        assert!(path.is_file(), "expected {} to be written", path.display());
    }
    let project_document: Value = serde_norway::from_str(
        &std::fs::read_to_string(project.join("evidence.yaml")).expect("read EvidenceProject"),
    )
    .expect("EvidenceProject parses");
    let source = &project_document["sources"]["source-b"];
    assert_eq!(source["type"], "http-json");
    assert_eq!(source["connection"], "source-b");
    assert_eq!(source["acquisitionPosture"], "record-transformed");

    // The normalized Source response shape carries the sample-derived bounds,
    // widened by the narrowing policy rather than copied.
    let schema = &source["response"]["shape"];
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(schema["properties"]["total"]["minimum"], 0);
    assert_eq!(schema["properties"]["total"]["maximum"], 10);
    // Two records is weak evidence of how long a page can be; the spec's own
    // page-size maximum is the stronger statement and wins for the top-level
    // collection.
    assert_eq!(schema["properties"]["records"]["maxItems"], 50);
    assert_eq!(
        schema["properties"]["records"]["items"]["properties"]["trackingId"]["maxLength"],
        16
    );

    let script = std::fs::read_to_string(&script_path).expect("read extract script");
    assert!(
        script.contains(r#"get_path(source_response, "/total")"#),
        "extract skeleton must read the selected scalar leaf: {script}"
    );
    assert!(
        script.contains(r#"get_path(source_response, "/records/0/trackingId")"#),
        "extract skeleton must substitute a numeric index for the `*` segment: {script}"
    );

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("evidencectl source suggest: draft for source `source-b`"),
        "the report belongs on stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "evidencectl source suggest {} --operation",
            path_argument(&project)
        )) && !stdout.contains("--project")
            && !stdout.contains("--openapi"),
        "a project reproduction uses its retained OpenAPI: {stdout}"
    );
    // The reproduce line is pasted into a shell, so a pointer carrying `*` is
    // quoted rather than left for the shell to expand.
    assert!(
        stdout.contains("--select '/records/*/trackingId'"),
        "the equivalent command must reproduce the selection, quoted: {stdout}"
    );

    // OpenAPI cannot establish governed source policy. The report must name
    // the completion and review still required for the generated artifacts.
    assert!(
        stdout.contains("Set the source origin.")
            && stdout.contains("Review the generated Source posture and default source limits.")
            && stdout.contains("Configure target-owned authentication.")
            && stdout.contains(
                "Complete selector bindings, the preparation Function, and request limits."
            ),
        "the report must name the completion and review work: {stdout}"
    );

    // Every adopted default is announced with its provenance, so a flag-driven
    // run is auditable without re-reading the generated files.
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("the sample response (widened)"),
        "adopted bounds must be announced with their provenance: {stderr}"
    );
    assert!(
        stderr.contains("a counter usually needs a more generous ceiling"),
        "a sampled integer ceiling must be flagged for review: {stderr}"
    );

    // A second identical run must not silently replace a draft an operator may
    // already have edited.
    let repeat = evidencectl(&arguments);
    assert!(
        !repeat.status.success(),
        "a second run must not overwrite the first draft"
    );
    assert!(
        stderr_of(&repeat).contains("EvidenceProject already defines Source `source-b`"),
        "unexpected refusal message: {}",
        stderr_of(&repeat)
    );
}

#[test]
fn a_project_always_uses_its_retained_openapi() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), OPENAPI_DOCUMENT);
    let other = write(workspace.path(), "other.openapi.yaml", OPENAPI_DOCUMENT);
    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        path_argument(&project),
        "--openapi".to_owned(),
        path_argument(&other),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/total".to_owned(),
    ]);
    assert_safe_usage_failure(&output);
    assert!(bundle_entries(&project).is_empty());
}

#[test]
fn source_suggest_requires_exactly_one_source() {
    let output = evidencectl(&["source".to_owned(), "suggest".to_owned()]);

    assert_safe_usage_failure(&output);
}

#[test]
fn prints_the_draft_without_a_project_and_writes_nothing() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let project = scaffold(workspace.path(), OPENAPI_DOCUMENT);
    let bundle_before = bundle_entries(&project);

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/records/*/trackingId".to_owned(),
        "--source-id".to_owned(),
        "source-c".to_owned(),
    ]);
    assert!(
        output.status.success(),
        "print-only source suggest failed: {}",
        stderr_of(&output)
    );

    let stdout = stdout_of(&output);
    for block in [
        "--- functions/source-c-prepare.rhai ---",
        "--- functions/source-c-extract.rhai ---",
        "--- the block to merge at the document root in evidence.yaml ---",
    ] {
        assert!(
            stdout.contains(block),
            "missing draft block {block}:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("sources:") && stdout.contains("source-c:"),
        "the pasteable source block belongs on stdout: {stdout}"
    );
    // With no sample, the page-size parameter is the only evidence of how long
    // the array can be, and the string leaf has none at all.
    assert!(
        stdout.contains("maxItems: 50"),
        "the page-size parameter must bound the array: {stdout}"
    );
    assert!(
        stdout.contains("TODO(evidencectl): /records/*/trackingId needs string length bounds"),
        "an underivable bound must stay an explicit TODO: {stdout}"
    );
    assert!(
        stderr_of(&output).contains("a page-size parameter in the spec"),
        "adopted page-size bound must be announced: {}",
        stderr_of(&output)
    );

    assert_eq!(
        bundle_entries(&project),
        bundle_before,
        "a print-only run must not write into any project"
    );
}

/// A page-size parameter bounds one page of the top-level collection. It says
/// nothing about how long an array *inside* a record can be, so a nested array
/// stays an explicit TODO instead of inheriting the page size.
#[test]
fn a_page_size_bounds_the_collection_but_not_an_array_inside_a_record() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/records/*/tags/*".to_owned(),
        "--source-id".to_owned(),
        "source-e".to_owned(),
    ]);
    assert!(
        output.status.success(),
        "source suggest failed: {}",
        stderr_of(&output)
    );

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("maxItems: 50"),
        "the page-size parameter must bound the collection: {stdout}"
    );
    assert!(
        stdout.contains("TODO(evidencectl): /records/*/tags needs maxItems"),
        "a nested array must not inherit the page size: {stdout}"
    );
    assert_eq!(
        stdout.matches("maxItems: 50").count(),
        1,
        "only the collection carries the page-size bound: {stdout}"
    );
}

/// When an operation advertises more than one size ceiling, the bound has to
/// be one a response can actually reach. The smallest ceiling is that bound;
/// the largest is a number the server will never return.
#[test]
fn the_smallest_advertised_size_ceiling_bounds_the_collection() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let document = OPENAPI_DOCUMENT.replace(
        "        - name: pageSize\n",
        "        - name: limit\n          in: query\n          schema:\n            type: integer\n            maximum: 200\n        - name: pageSize\n",
    );
    let openapi = write(workspace.path(), "records.openapi.yaml", &document);

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/records/*/trackingId".to_owned(),
        "--source-id".to_owned(),
        "source-f".to_owned(),
    ]);
    assert!(
        output.status.success(),
        "source suggest failed: {}",
        stderr_of(&output)
    );

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("maxItems: 50"),
        "the smallest ceiling must bound the collection: {stdout}"
    );
    assert!(
        !stdout.contains("maxItems: 200"),
        "a ceiling the response cannot reach must not become the bound: {stdout}"
    );
}

/// The runtime's fixed-request method is an enumeration of two. An operation
/// outside it is refused by name, before any file is drafted.
#[test]
fn an_operation_outside_the_runtime_method_enum_is_refused_by_name() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "PATCH /records".to_owned(),
        "--select".to_owned(),
        "/total".to_owned(),
    ]);
    assert!(
        !output.status.success(),
        "PATCH must not draft a source: {}",
        stdout_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("PATCH") && stderr.contains("GET") && stderr.contains("POST"),
        "the refusal must name the method and the two admitted ones: {stderr}"
    );
}

#[test]
fn a_non_interactive_run_names_the_flags_it_needs() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);

    // `output()` gives the child a null stdin and piped stdout, so neither is a
    // terminal and the interactive selection cannot run.
    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
    ]);
    assert!(
        !output.status.success(),
        "a non-interactive run without the selection flags must fail"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--operation") && stderr.contains("--select"),
        "the error must name every missing flag: {stderr}"
    );
}

/// The classification of `evidence check` is reported in plain words. The
/// runtime is represented here by a stub printing one of its fixed messages,
/// so the assertion is about `evidencectl`'s reporting and not about a
/// deployment project that is not frozen or provisioned yet.
fn evidencectl(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn parameter(name: &str, location: &str, required: bool, scalar_type: &str) -> Value {
    serde_json::json!({
        "name": name,
        "in": location,
        "required": required,
        "schema": {"type": scalar_type}
    })
}

fn content_parameter(name: &str, location: &str, required: bool) -> Value {
    serde_json::json!({
        "name": name,
        "in": location,
        "required": required,
        "content": {"application/json": {"schema": {"type": "string"}}}
    })
}

fn external_schema_parameter(name: &str, location: &str, required: bool) -> Value {
    serde_json::json!({
        "name": name,
        "in": location,
        "required": required,
        "schema": {"$ref": "https://schemas.example.invalid/value.json"}
    })
}

fn json_body(required: bool, schema: Value) -> Value {
    serde_json::json!({
        "required": required,
        "content": {"application/json": {"schema": schema}}
    })
}

fn form_body(required: bool) -> Value {
    serde_json::json!({
        "required": required,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type":"object",
                    "additionalProperties":false,
                    "required":["reference"],
                    "properties":{"reference":{"type":"string"}}
                }
            }
        }
    })
}

fn external_json_body(required: bool) -> Value {
    serde_json::json!({
        "required": required,
        "content": {
            "application/json": {
                "schema": {"$ref": "https://schemas.example.invalid/body.json"}
            }
        }
    })
}

fn request_openapi(
    method: &str,
    path: &str,
    parameters: Vec<Value>,
    request_body: Option<Value>,
) -> String {
    let mut operation = serde_json::json!({
        "parameters": parameters,
        "responses": {
            "200": {
                "description": "record",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["allowed"],
                            "properties": {"allowed": {"type": "boolean"}}
                        }
                    }
                }
            }
        }
    });
    if let Some(request_body) = request_body {
        operation["requestBody"] = request_body;
    }
    let mut path_item = serde_json::Map::new();
    path_item.insert(method.to_ascii_lowercase(), operation);
    let mut paths = serde_json::Map::new();
    paths.insert(path.to_owned(), Value::Object(path_item));
    serde_norway::to_string(&serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Mapped source", "version": "1"},
        "paths": paths
    }))
    .expect("OpenAPI renders")
}

fn request_openapi_with_path_parameters(
    method: &str,
    path: &str,
    path_parameters: Vec<Value>,
    operation_parameters: Vec<Value>,
    request_body: Option<Value>,
) -> String {
    let document = request_openapi(method, path, operation_parameters, request_body);
    let mut document: Value = serde_norway::from_str(&document).expect("parse generated OpenAPI");
    document["paths"][path]["parameters"] = Value::Array(path_parameters);
    serde_norway::to_string(&document).expect("OpenAPI renders")
}

fn mapped_suggest(project: &Path, mappings: &[String]) -> Output {
    let openapi: Value = serde_norway::from_str(
        &std::fs::read_to_string(project.join("source.openapi.yaml")).expect("read OpenAPI"),
    )
    .expect("parse OpenAPI");
    let (path, path_item) = openapi["paths"]
        .as_object()
        .and_then(|paths| paths.iter().next())
        .expect("one path");
    let method = ["get", "post"]
        .into_iter()
        .find(|method| path_item.get(*method).is_some())
        .expect("GET or POST operation");
    let mut arguments = vec![
        "source".to_owned(),
        "suggest".to_owned(),
        "--operation".to_owned(),
        format!("{} {path}", method.to_ascii_uppercase()),
        "--select".to_owned(),
        "/allowed".to_owned(),
        "--source-id".to_owned(),
        "mapped".to_owned(),
    ];
    for mapping in mappings {
        arguments.push("--map-selector".to_owned());
        arguments.push(mapping.clone());
    }
    arguments.push(path_argument(project));
    evidencectl(&arguments)
}

fn project_snapshot(project: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut paths = vec![project.join("evidence.yaml")];
    paths.extend(
        std::fs::read_dir(project.join("functions"))
            .expect("read Functions")
            .map(|entry| entry.expect("Function entry").path()),
    );
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(project)
                .expect("project path")
                .to_path_buf();
            let bytes = std::fs::read(&path).expect("read project artifact");
            (relative, bytes)
        })
        .collect()
}

fn assert_mapping_failure_is_atomic(
    project: &Path,
    mappings: &[String],
    expected: &str,
    case: &str,
) {
    let before = project_snapshot(project);
    let output = mapped_suggest(project, mappings);
    assert!(!output.status.success(), "{case} unexpectedly succeeded");
    assert!(
        stderr_of(&output).contains(expected),
        "{case}: expected `{expected}` in {}",
        stderr_of(&output)
    );
    assert_eq!(
        project_snapshot(project),
        before,
        "{case} mutated the project after refusal"
    );
}

fn edit_project(project: &Path, edit: impl FnOnce(&mut Value)) {
    let path = project.join("evidence.yaml");
    let mut document: Value = serde_json::from_slice(&std::fs::read(&path).expect("read project"))
        .expect("parse project JSON");
    edit(&mut document);
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&document).expect("render project JSON"),
    )
    .expect("write project");
}

fn add_string_selector_field(project: &Path, field: &str, maximum_bytes: u64) {
    edit_project(project, |document| {
        document["selectorProfiles"]["subject-reference-v1"]["fields"][field] = serde_json::json!({
            "type":"string", "minimumBytes":1, "maximumBytes":maximum_bytes
        });
        document["selectorProfiles"]["subject-reference-v1"]["maximumAggregateBytes"] =
            serde_json::json!(8192);
    });
}

fn set_reference_selector_maximum(project: &Path, maximum_bytes: u64) {
    edit_project(project, |document| {
        document["selectorProfiles"]["subject-reference-v1"]["fields"]["reference"]
            ["maximumBytes"] = serde_json::json!(maximum_bytes);
        document["selectorProfiles"]["subject-reference-v1"]["maximumAggregateBytes"] =
            serde_json::json!(8192);
    });
}

fn set_integer_selector_bounds(project: &Path, minimum: i64, maximum: i64) {
    edit_project(project, |document| {
        document["selectorProfiles"]["integer-v1"]["fields"]["value"]["minimum"] =
            serde_json::json!(minimum);
        document["selectorProfiles"]["integer-v1"]["fields"]["value"]["maximum"] =
            serde_json::json!(maximum);
    });
}

/// Create the only precondition `source suggest --project` requires: an
/// existing project directory. `new` is tested separately and now owns the
/// OpenAPI path itself.
fn scaffold(root: &Path, openapi: &str) -> PathBuf {
    let project = root.join("project");
    std::fs::create_dir(&project).expect("project directory");
    std::fs::create_dir(project.join("functions")).expect("Function directory");
    let document = serde_json::json!({
        "apiVersion":"id.registrystack.org/formats/evidence/project/v1alpha1",
        "kind":"EvidenceProject",
        "id":"suggest-e2e",
        "selectorProfiles":{
            "subject-reference-v1":{"maximumAggregateBytes":128,"fields":{"reference":{"type":"string","minimumBytes":1,"maximumBytes":128}}},
            "integer-v1":{"maximumAggregateBytes":32,"fields":{"value":{"type":"integer","minimum":0,"maximum":100}}}
        },
        "functions":[
            {"id":"baseline-prepare","interface":"source-prepare/v1","source":"functions/baseline-prepare.rhai"},
            {"id":"baseline-extract","interface":"source-extract/v1","source":"functions/baseline-extract.rhai"},
            {"id":"baseline-derive","interface":"assertion-derive/v1","source":"functions/baseline-derive.rhai"}
        ],
        "sources":{"baseline":{
            "type":"http-json","connection":"baseline","acquisitionPosture":"field-projected",
            "selectors":[{"role":"subject","profiles":["subject-reference-v1"]}],
            "request":{"method":"POST","path":"/v1/facts","fixedHeaders":[]},
            "prepare":{"function":"baseline-prepare"},"extract":{"function":"baseline-extract"},
            "response":{"projection":["/allowed"],"shape":{"type":"object","required":["allowed"],"properties":{"allowed":{"type":"boolean"}}},"maximumBytes":4096},
            "facts":{"allowed":{"type":"boolean"}},
            "limits":{"attemptTimeoutMilliseconds":1000,"maximumConcurrency":1}
        }},
        "assertionDefinitions":{"baseline":{
            "question":"Is the baseline condition satisfied?",
            "semantics":{"requirement":"urn:example:requirements:baseline:v1","kind":"criterion","evidenceType":"urn:example:evidence-types:baseline:v1","referenceFrameworks":["urn:example:frameworks:baseline:v1"]},
            "purpose":"testing","grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audiences:test"]},
            "subjects":[{"role":"subject","selectors":["subject-reference-v1","integer-v1"]}],
            "acquisition":{"type":"single","source":"baseline"},"derive":{"function":"baseline-derive"},
            "outputs":{"allowed":{"concept":"urn:example:concepts:allowed","type":"boolean"}},
            "validitySeconds":300,"subjectBinding":"audience-scoped","representations":["signed-jws"]
        }}
    });
    std::fs::write(
        project.join("evidence.yaml"),
        serde_json::to_vec_pretty(&document).expect("EvidenceProject JSON"),
    )
    .expect("EvidenceProject");
    for (name, script) in [
        ("baseline-prepare", "fn prepare(selectors, context) { #{query: [], body: ()} }\n"),
        ("baseline-extract", "fn extract(source_response, context) { #{outcome: \"match\", facts: #{allowed: source_response[\"allowed\"]}} }\n"),
        ("baseline-derive", "fn derive(facts, selectors, context) { [#{output: \"allowed\", value: facts[\"allowed\"]}] }\n"),
    ] {
        std::fs::write(project.join(format!("functions/{name}.rhai")), script)
            .expect("Function script");
    }
    std::fs::write(project.join("source.openapi.yaml"), openapi).expect("retained OpenAPI");
    project
}

fn write(root: &Path, name: &str, contents: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, contents).expect("writing a test input");
    path
}

/// Every path beneath the project's bundle directory, sorted, so a test can
/// prove a run wrote nothing.
fn bundle_entries(project: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    let mut pending = vec![project.join("bundle")];
    while let Some(directory) = pending.pop() {
        let Ok(children) = std::fs::read_dir(&directory) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            entries.push(path);
        }
    }
    entries.sort();
    entries
}

fn path_argument(path: &Path) -> String {
    path.to_str()
        .expect("test paths are valid UTF-8")
        .to_owned()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

fn assert_safe_usage_failure(output: &Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        stderr_of(output),
        "error[evidencectl.usage] command line $: The Evidence command line is incomplete or contains conflicting or unsupported arguments.\n  next: Run evidencectl --help or the selected command with --help, then retry using the documented arguments.\n"
    );
}

/// `--list-pointers` prints exactly the set `--select` accepts for the
/// selected operation and response, one pointer per line for a human and a
/// machine-readable array for JSON, without drafting anything.
#[test]
fn list_pointers_prints_the_selectable_leaves_in_both_formats() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    const EXPECTED: [&str; 5] = [
        "/records/*/recordedOn",
        "/records/*/status",
        "/records/*/tags/*",
        "/records/*/trackingId",
        "/total",
    ];

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--list-pointers".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout_of(&output),
        EXPECTED
            .iter()
            .map(|pointer| format!("  {pointer}\n"))
            .collect::<String>()
    );

    let output = evidencectl(&[
        "--format".to_owned(),
        "json".to_owned(),
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--list-pointers".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stderr_of(&output).is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON report");
    assert_eq!(
        report,
        serde_json::json!({
            "apiVersion": "id.registrystack.org/formats/evidence/ctl-report/v1alpha1",
            "command": "source suggest",
            "diagnostics": [],
            "kind": "EvidenceCtlReport",
            "notes": [],
            "ok": true,
            "pointers": EXPECTED,
            "status": "complete",
            "version": registry_platform_buildinfo::DISPLAY_VERSION,
        })
    );

    assert!(
        !workspace.path().join("sources").exists(),
        "a pointer listing drafts nothing"
    );

    // The leaves come from one chosen operation's response, so a listing
    // without --operation is a usage error rather than an interactive prompt.
    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--list-pointers".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout_of(&output).is_empty());
}

/// An unknown `--select` pointer keeps its human listing on stderr and gains
/// a machine-readable failure whose diagnostic names the pointer and carries
/// the valid pointers as a sibling field.
#[test]
fn an_unknown_select_failure_lists_the_available_pointers_in_both_formats() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let base = [
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/not-a-leaf".to_owned(),
    ];

    let output = evidencectl(&{
        let mut arguments = vec!["source".to_owned(), "suggest".to_owned()];
        arguments.extend(base.iter().cloned());
        arguments
    });
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("`--select /not-a-leaf` names nothing in this response schema"),
        "the refusal names the pointer: {stderr}"
    );
    assert!(
        stderr.contains("\n  /total\n"),
        "the human listing still names the valid pointers: {stderr}"
    );

    let output = evidencectl(&{
        let mut arguments = vec![
            "--format".to_owned(),
            "json".to_owned(),
            "source".to_owned(),
            "suggest".to_owned(),
        ];
        arguments.extend(base.iter().cloned());
        arguments
    });
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON failure");
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "evidencectl.source.select-unknown");
    assert_eq!(diagnostic["artifact"], "source suggest");
    assert_eq!(diagnostic["path"], "$.select");
    assert!(
        diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains("/not-a-leaf")),
        "the message names the unknown pointer: {diagnostic}"
    );
    assert_eq!(
        diagnostic["availablePointers"],
        serde_json::json!([
            "/records/*/recordedOn",
            "/records/*/status",
            "/records/*/tags/*",
            "/records/*/trackingId",
            "/total",
        ])
    );
}

/// A flag-driven run answers one JSON object on stdout: the source id, the
/// files it wrote, the human report, and the equivalent command. The draft
/// blocks stay off stdout so the report is the only thing to parse.
#[test]
fn a_delivered_draft_reports_the_written_files_and_equivalent_command_in_json() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = scaffold(workspace.path(), OPENAPI_DOCUMENT);

    let arguments = vec![
        "--format".to_owned(),
        "json".to_owned(),
        "source".to_owned(),
        "suggest".to_owned(),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/total".to_owned(),
        "--source-id".to_owned(),
        "source-b".to_owned(),
        path_argument(&project),
    ];
    let output = evidencectl(&arguments);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout_of(&output),
        stderr_of(&output)
    );
    // The provenance announcements a human run prints on stderr travel in
    // the report's notes, so JSON mode leaves stderr silent.
    assert!(
        stderr_of(&output).is_empty(),
        "JSON mode writes nothing to stderr: {}",
        stderr_of(&output)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON report");
    assert!(
        report["notes"]
            .as_array()
            .is_some_and(|notes| !notes.is_empty()),
        "the provenance announcements travel in the notes: {report}"
    );
    assert_eq!(report["command"], "source suggest");
    assert_eq!(report["ok"], Value::Bool(true));
    assert_eq!(report["status"], "complete");
    assert_eq!(report["sourceId"], "source-b");
    let files = report["files"].as_array().expect("written files");
    assert_eq!(
        files.len(),
        3,
        "two Functions plus the updated EvidenceProject"
    );
    for relative in [
        "functions/source-b-prepare.rhai",
        "functions/source-b-extract.rhai",
        "evidence.yaml",
    ] {
        assert!(
            files.contains(&serde_json::json!(project
                .join(relative)
                .display()
                .to_string())),
            "missing {relative}: {files:?}"
        );
    }
    assert!(
        report["report"]
            .as_str()
            .is_some_and(|report| report.contains("draft for source `source-b`")),
        "the report carries what the human renderer prints: {}",
        report["report"]
    );
    assert!(
        report["equivalentCommand"]
            .as_str()
            .is_some_and(|command| command.starts_with(&format!(
                "evidencectl source suggest {} --operation",
                path_argument(&project)
            ))),
        "the equivalent command reproduces the run: {}",
        report["equivalentCommand"]
    );
    assert!(
        !stdout_of(&output).contains("--- functions/source-b-prepare.rhai ---"),
        "the draft blocks stay off JSON stdout"
    );

    // A print-only run reports the same shape with nothing written.
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let output = evidencectl(&[
        "--format".to_owned(),
        "json".to_owned(),
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/total".to_owned(),
        "--source-id".to_owned(),
        "source-c".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).expect("one JSON report");
    assert_eq!(report["sourceId"], "source-c");
    assert_eq!(report["files"], serde_json::json!([]));
}
