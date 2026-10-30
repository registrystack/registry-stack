// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl compile`: the concrete OpenAPI 3.1
//! document a deployment serves, written beside the project and held
//! byte-identical by `--check` (`products/adapter/CONCEPT.md` section 7).

use registry_record::{
    RegistryRecord, RegistryRecordCollectionResponse, RegistryRecordMeta, RegistryRecordPageInfo,
    RegistryRecordSingleResponse,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The minimal fixture project's directory.
fn minimal_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal")
        .to_path_buf()
}

/// The maintained example's project file.
fn example_project() -> PathBuf {
    repo_root().join("products/adapter/examples/dhis2-tracker/project.yaml")
}

/// The maintained profile and pack the example pins.
fn example_profile() -> PathBuf {
    repo_root().join("products/adapter/profiles/breg-records/profile.yaml")
}

fn example_pack() -> PathBuf {
    repo_root().join("products/adapter/packs/dhis2-tracker/pack.yaml")
}

/// Run one invocation in JSON mode and return its exit code, its report
/// (null when stdout carried no report), and its stderr.
fn run_json(arguments: &[&str]) -> (ExitCode, Value, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
    assert_envelope(&stdout, &report, exit);
    (exit, report, stderr)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that
/// order, then names its format; `ok` is true exactly when the process
/// exits zero, and a report that is not ok carries at least one
/// diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(5)
        .collect::<Vec<_>>();
    assert_eq!(
        head,
        ["ok", "command", "status", "apiVersion", "kind"],
        "{text}"
    );
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/adapter/ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "AdapterCtlReport");
    assert!(report["command"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(report["status"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{text}"
            );
        }
    }
}

/// Recursively copy a fixture tree (a handful of small files).
fn copy_fs(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fs(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Copy one fixture tree into a fresh directory and hand the copy's
/// `project.yaml` back with the directory guard that keeps it alive.
fn copied_tree(from: &Path) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("project");
    copy_fs(from, &copy);
    let project = copy.join("project.yaml").to_str().unwrap().to_owned();
    (root, project)
}

/// Compile a project and return the parsed document plus its bytes.
fn compile(project: &str, extra: &[&str]) -> (Value, Vec<u8>) {
    let mut arguments = vec!["compile", project];
    arguments.extend_from_slice(extra);
    let (exit, report, stderr) = run_json(&arguments);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    let output = report["output"]
        .as_str()
        .expect("the output path")
        .to_owned();
    let bytes = std::fs::read(&output).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    (document, bytes)
}

/// The minimal fixture project compiles: the document is written beside
/// the project, carries one concrete operation for the one bound pair,
/// the bearer scheme, and the problem schema, and nothing else.
#[test]
fn the_minimal_fixture_project_compiles() {
    let (root, project) = copied_tree(&minimal_dir());
    let (document, bytes) = compile(&project, &[]);

    let output = root.path().join("project/generated/openapi.json");
    assert_eq!(
        std::fs::read(&output).unwrap(),
        bytes,
        "the default output is <project-dir>/generated/openapi.json"
    );
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(
        document["info"],
        json!({"title": "case-deployment", "version": "1"})
    );

    // One concrete operation for the one bound (operation, record type)
    // pair: the record type is substituted into the path, so no template
    // placeholder remains (D6, CONCEPT section 7).
    let paths = document["paths"].as_object().expect("paths");
    assert_eq!(paths.len(), 1, "{paths:?}");
    let operation = &document["paths"]["/v2/cases/case"]["get"];
    assert_eq!(operation["operationId"], "cases-get.case");
    assert_eq!(operation["parameters"], json!([]));
    assert_eq!(operation["security"], json!([{"bearerAuth": []}]));
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["record"]["properties"]["national_id"],
        json!({"type": "string"})
    );

    // The profile's problem envelope becomes the shared problem schema.
    assert_eq!(
        document["components"]["schemas"]["Problem"],
        json!({
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
            "additionalProperties": false,
        })
    );
    assert_eq!(
        document["components"]["securitySchemes"]["bearerAuth"],
        json!({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"})
    );
}

/// The profile's problems list becomes the error responses of every
/// operation (R7, CONCEPT section 8.11.6): one response per distinct
/// status, each answering the shared problem schema, described by the
/// first problem carrying that status. Two problems sharing 502 prove the
/// statuses, not the codes, key the responses.
#[test]
fn error_responses_come_from_the_profile_problems_list() {
    let (root, project) = copied_tree(&minimal_dir());
    let (document, _) = compile(&project, &[]);
    let _ = root;

    let responses = &document["paths"]["/v2/cases/case"]["get"]["responses"];
    let keys: Vec<&str> = responses
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["200", "422", "500", "502"]);
    assert_eq!(
        responses["200"]["description"],
        "The operation's response envelope for the bound record type."
    );
    assert_eq!(
        responses,
        &json!({
            "200": responses["200"].clone(),
            "422": {
                "description": "the request or its mapping was refused",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Problem"}
                    }
                }
            },
            "500": {
                "description": "the facade refused the call",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Problem"}
                    }
                }
            },
            "502": {
                "description": "the source could not be reached",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Problem"}
                    }
                }
            }
        }),
        "the responses are the success response plus one per problem status"
    );

    // Every operation carries the error responses, not only the first.
    for item in document["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            assert!(
                operation["responses"]["502"]["content"]["application/json"]["schema"]
                    .get("$ref")
                    .is_some(),
                "every operation answers the profile's problems"
            );
        }
    }
}

/// The document is pretty-printed with sorted keys and a trailing
/// newline, so its diff is the contract review, and two runs over the
/// same project give identical bytes.
#[test]
fn two_runs_are_byte_identical_and_pretty_sorted() {
    let (root, project) = copied_tree(&minimal_dir());
    let (_, first) = compile(&project, &[]);
    let (_, second) = compile(
        &project,
        &["--output", root.path().join("again.json").to_str().unwrap()],
    );
    assert_eq!(first, second, "two runs give identical bytes");

    let text = String::from_utf8(first).unwrap();
    assert!(text.ends_with("}\n"), "the document ends with a newline");
    assert!(text.contains("\n  \"openapi\""), "two-space indent");
    let document: Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<&str> = document
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "keys are written in sorted order");
    // Round-tripping through a sorted-map parser is byte-stable: the
    // text form itself is the canonical one.
    assert_eq!(
        serde_json::to_string_pretty(&document).unwrap() + "\n",
        text
    );
}

/// `--check` passes on identical bytes and refuses on a one-byte change.
#[test]
fn check_refuses_a_one_byte_change() {
    let (root, project) = copied_tree(&minimal_dir());
    let (_, bytes) = compile(&project, &[]);
    let (exit, report, _) = run_json(&["compile", &project, "--check"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["check"], json!(true));

    let output = root.path().join("project/generated/openapi.json");
    let mut drifted = bytes.clone();
    let last = drifted.len() - 2;
    drifted[last] = b' ';
    std::fs::write(&output, drifted).unwrap();
    let (exit, report, _) = run_json(&["compile", &project, "--check"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.compile.drift");

    // A missing file counts as drift, like the schemas gate.
    std::fs::remove_file(&output).unwrap();
    let (exit, report, _) = run_json(&["compile", &project, "--check"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.compile.drift");
}

/// A project a workspace check refuses is not compiled: the reader's and
/// the pure checks' findings refuse the run and nothing is written.
#[test]
fn a_refused_project_writes_nothing() {
    let (root, project) = copied_tree(&minimal_dir());
    let text = std::fs::read_to_string(&project).unwrap();
    std::fs::write(
        &project,
        text.replace("recordType: case", "recordType: ghost"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["compile", &project]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["status"], "domain-refusal");
    assert!(report["diagnostics"]
        .as_array()
        .is_some_and(|findings| !findings.is_empty()));
    assert!(
        !root.path().join("project/generated/openapi.json").exists(),
        "a refused project writes no document"
    );
}

/// A profile operation no binding binds emits no path (D6: the contract
/// holds only bound operations).
#[test]
fn an_unbound_profile_operation_emits_no_path() {
    let (root, project) = copied_tree(&minimal_dir());
    let text = std::fs::read_to_string(&project).unwrap();
    let unbound = text.replace("recordType: case", "recordType: case\n    x-remove: true");
    std::fs::write(&project, unbound).unwrap();
    // Removing the binding by hand: drop the whole bindings entry.
    let text = std::fs::read_to_string(&project).unwrap();
    let start = text.find("bindings:").expect("the bindings block");
    let end = text.find("accessProfiles:").expect("the access profiles");
    std::fs::write(&project, format!("{}{}", &text[..start], &text[end..])).unwrap();
    let (document, _) = compile(&project, &[]);
    assert_eq!(
        document["paths"],
        json!({}),
        "an operation with no binding emits no path"
    );
    let _ = root;
}

/// The maintained example compiles under breg-records: concrete person
/// paths, pagination parameters with the profile's names and bounds, the
/// request body on the write, unbound write operations absent, and the
/// parameterized parts typed as strings, never the stand-in consts.
#[test]
fn the_maintained_example_compiles_under_breg_records() {
    let (root, project) = copied_tree(example_project().parent().unwrap());
    let profile = example_profile().to_str().unwrap().to_owned();
    let pack = example_pack().to_str().unwrap().to_owned();
    let (document, _) = compile(&project, &["--profile", &profile, "--pack", &pack]);
    let _ = root;

    let paths = document["paths"].as_object().expect("paths");
    // `/v1/records/person` carries search (get) and create (post);
    // `/v1/records/person/{record_id}` carries get.
    assert_eq!(paths.len(), 2, "{paths:?}");
    let search = &document["paths"]["/v1/records/person"]["get"];
    assert_eq!(search["operationId"], "records-search.person");
    let parameters = search["parameters"].as_array().expect("parameters");
    assert_eq!(
        parameters,
        &vec![
            json!({
                "name": "cursor",
                "in": "query",
                "required": false,
                "schema": {"type": "string"},
            }),
            json!({
                "name": "limit",
                "in": "query",
                "required": false,
                "schema": {"type": "integer", "minimum": 1, "maximum": 1000},
            }),
        ],
        "the profile's cursor and page-size names and bounds, and no others"
    );

    let get = &document["paths"]["/v1/records/person/{record_id}"]["get"];
    assert_eq!(get["operationId"], "records-get.person");
    assert_eq!(
        get["parameters"],
        json!([{
            "name": "record_id",
            "in": "path",
            "required": true,
            "schema": {"type": "string"},
        }])
    );

    let create = &document["paths"]["/v1/records/person"]["post"];
    assert_eq!(create["operationId"], "records-create.person");
    assert_eq!(
        create["requestBody"]["content"]["application/json"]["schema"]["properties"]["data"]
            ["properties"]["org_unit"],
        json!({"type": "string"})
    );
    assert_eq!(create["requestBody"]["required"], json!(true));

    // records-update and records-patch are unbound: no path carries them.
    for (path, item) in paths {
        for method in item.as_object().unwrap().keys() {
            let id = item[method]["operationId"].as_str().unwrap();
            assert!(
                !id.starts_with("records-update.") && !id.starts_with("records-patch."),
                "{path} {method} carries an unbound operation"
            );
        }
        let _ = path;
    }

    // A parameterized part is a deployment value the contract cannot
    // know: the schema types it as a string, never the stand-in const.
    let meta = &document["paths"]["/v1/records/person/{record_id}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]["properties"]["meta"]["properties"];
    assert_eq!(meta["registryIdentifier"], json!({"type": "string"}));
    assert_eq!(meta["datasetIdentifier"], json!({"type": "string"}));
    assert_eq!(meta["entityTypeIdentifier"], json!({"type": "string"}));
}

/// The breg-records envelope matches the `registry-record` serialization
/// goldens at the envelope level: a single response and a collection
/// response serialize to exactly the members the compiled schemas
/// declare, with the same scalar shapes (CONCEPT section 13.6).
#[test]
fn breg_records_envelopes_match_registry_record_goldens() {
    let (root, project) = copied_tree(example_project().parent().unwrap());
    let profile = example_profile().to_str().unwrap().to_owned();
    let pack = example_pack().to_str().unwrap().to_owned();
    let (document, _) = compile(&project, &["--profile", &profile, "--pack", &pack]);
    let _ = root;

    let record = RegistryRecord {
        record_identifier: "r-1".to_owned(),
        revision_identifier: "1".to_owned(),
        domain_data: BTreeMap::from([
            ("org_unit".to_owned(), json!("OqVpUaAYv2B")),
            ("tracked_entity_type".to_owned(), json!("person")),
            ("created_at".to_owned(), json!("2026-01-05T10:00:00.000")),
            ("updated_at".to_owned(), json!("2026-02-11T09:30:00.000")),
        ]),
        extensions: BTreeMap::new(),
    };
    let meta = RegistryRecordMeta {
        registry_identifier: "registry.example".to_owned(),
        dataset_identifier: "directory".to_owned(),
        entity_type_identifier: "person".to_owned(),
        extensions: BTreeMap::new(),
    };
    let single: Value = serde_json::to_value(RegistryRecordSingleResponse {
        json_ld_context: None,
        data: record.clone(),
        meta: meta.clone(),
        extensions: BTreeMap::new(),
    })
    .unwrap();
    let collection: Value = serde_json::to_value(RegistryRecordCollectionResponse {
        json_ld_context: None,
        items: vec![record],
        page_info: RegistryRecordPageInfo {
            next_cursor: Some("cursor".to_owned()),
            extensions: BTreeMap::new(),
        },
        meta,
        extensions: BTreeMap::new(),
    })
    .unwrap();

    let schema_of = |operation: &str| {
        let mut found = Vec::new();
        for item in document["paths"].as_object().unwrap().values() {
            for op in item.as_object().unwrap().values() {
                if op["operationId"].as_str() == Some(operation) {
                    found.push(
                        op["responses"]["200"]["content"]["application/json"]["schema"].clone(),
                    );
                }
            }
        }
        assert_eq!(found.len(), 1, "one concrete {operation} operation");
        found.remove(0)
    };
    let single_schema = schema_of("records-get.person");
    let collection_schema = schema_of("records-search.person");

    // The golden's envelope members are exactly the schema's, and the
    // shared scalars carry the same shapes.
    let single_keys = |value: &Value| {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort_unstable();
        keys
    };
    assert_eq!(
        single_keys(&single_schema["properties"]),
        single_keys(&single),
        "a single response's members are the compiled schema's"
    );
    assert_eq!(
        single_keys(&collection_schema["properties"]),
        single_keys(&collection),
        "a collection response's members are the compiled schema's"
    );
    assert_eq!(
        collection_schema["properties"]["pageInfo"]["properties"]["nextCursor"],
        json!({"type": "string"})
    );
    let schema_meta = &collection_schema["properties"]["meta"]["properties"];
    let golden_meta = single["meta"].as_object().unwrap();
    for key in [
        "registryIdentifier",
        "datasetIdentifier",
        "entityTypeIdentifier",
    ] {
        assert_eq!(schema_meta[key], json!({"type": "string"}));
        assert!(golden_meta[key].is_string());
    }
}

/// The compiled document keeps the shape of BReg's generated per-package
/// OpenAPI: the same version, the same bearer scheme, and likewise
/// concrete per-record-type paths (CONCEPT section 13.6).
#[test]
fn the_document_keeps_the_breg_generated_shape() {
    let breg_path = repo_root().join("products/breg/generated/minimal/generated/openapi.json");
    let breg: Value = serde_json::from_slice(&std::fs::read(&breg_path).unwrap()).unwrap();

    let (root, project) = copied_tree(example_project().parent().unwrap());
    let profile = example_profile().to_str().unwrap().to_owned();
    let pack = example_pack().to_str().unwrap().to_owned();
    let (document, _) = compile(&project, &["--profile", &profile, "--pack", &pack]);
    let _ = root;

    assert_eq!(document["openapi"], breg["openapi"]);
    assert_eq!(
        document["components"]["securitySchemes"], breg["components"]["securitySchemes"],
        "the same bearer scheme BReg serves"
    );
    // BReg enumerates concrete record paths (`/v1/records/contacts`); the
    // adapter's paths are concrete the same way, with no `{type}`
    // template left for the record-type slot.
    assert!(breg["paths"]
        .as_object()
        .unwrap()
        .keys()
        .any(|path| path.starts_with("/v1/records/")));
    for path in document["paths"].as_object().unwrap().keys() {
        assert!(
            !path.contains("{type}"),
            "the record-type slot is concrete: {path}"
        );
    }
}

/// A second profile over its own pack compiles with its own paths,
/// envelope, and pagination names, proving the target API is
/// configuration (CONCEPT section 13.6).
#[test]
fn the_case_api_corpus_base_compiles_with_foreign_names() {
    let corpus = repo_root().join("products/adapter/fixtures/corpus/base");
    let (root, project) = copied_tree(&corpus);
    let (document, _) = compile(&project, &[]);
    let _ = root;

    let get = &document["paths"]["/v2/cases/case/{case_id}"]["get"];
    assert_eq!(get["operationId"], "cases-get.case");
    assert_eq!(
        get["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["case"]
            ["properties"]["case_type"],
        json!({"type": "string"})
    );
}

/// The second-target-profile experiment compiles: a third convention set
/// (FHIR paths, Bundle envelope, `_page_token` and `_count`) over its own
/// project.
#[test]
fn the_second_target_experiment_compiles() {
    let experiment = repo_root().join("products/adapter/experiments/second-target-profile");
    let (root, project) = copied_tree(&experiment);
    let (document, _) = compile(&project, &[]);
    let _ = root;

    let search = &document["paths"]["/fhir/household"]["get"];
    assert_eq!(search["operationId"], "fhir-search-type.household");
    let names: Vec<&str> = search["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["_count", "_page_token"]);
    let count = &search["parameters"][0];
    assert_eq!(
        count["schema"],
        json!({"type": "integer", "minimum": 1, "maximum": 500})
    );
    assert_eq!(
        search["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["resourceType"],
        json!({"type": "string", "const": "Bundle"})
    );
}

/// Two bindings whose concrete paths collide refuse the compile with the
/// collision diagnostic.
#[test]
fn colliding_concrete_paths_refuse() {
    let (root, project) = copied_tree(&minimal_dir());
    let text = std::fs::read_to_string(&project).unwrap();
    // A second binding of the same operation and record type under
    // another id: the same concrete path twice.
    let colliding = text.replace(
        "bindings:\n  - id: find-cases",
        "bindings:\n  - id: find-cases-again\n    operation: cases-get\n    recordType: case\n    route: fetchCases\n    maximumUpstreamCalls: 5\n  - id: find-cases",
    );
    std::fs::write(&project, colliding).unwrap();
    let (exit, report, _) = run_json(&["compile", &project]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "adapterctl.compile.path-collision"
    );
    assert!(
        !root.path().join("project/generated/openapi.json").exists(),
        "a colliding project writes no document"
    );
}
