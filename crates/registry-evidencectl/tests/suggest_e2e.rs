//! `evidencectl source suggest` end to end, through the real binary.
//!
//! Every case here drives the installed `evidencectl` executable
//! non-interactively, the way an operator reproduces a reviewed interactive
//! run: a synthetic OpenAPI document and a synthetic sample response are
//! written into a temporary directory, and the command is asked to draft one
//! source from them. Nothing here reaches the network, and no sample value is
//! expected in any assertion: only bounds derived from the sample are.

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

#[test]
fn drafts_into_a_project_and_then_refuses_to_overwrite_the_draft() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let sample = write(workspace.path(), "records.sample.json", SAMPLE_RESPONSE);
    let project = scaffold(workspace.path());

    let arguments = vec![
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
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
        "--project".to_owned(),
        path_argument(&project),
    ];
    let output = evidencectl(&arguments);
    assert!(
        output.status.success(),
        "source suggest failed: {}",
        stderr_of(&output)
    );

    let bundle = project.join("bundle");
    let schema_path = bundle.join("schemas/source-b-response.schema.yaml");
    let script_path = bundle.join("adapters/source-b-extract.rhai");
    let facts_path = bundle.join("schemas/source-b-facts.schema.yaml");
    for path in [&schema_path, &script_path, &facts_path] {
        assert!(path.is_file(), "expected {} to be written", path.display());
    }

    // The response schema parses as YAML and carries the sample-derived
    // bounds, widened by the narrowing policy rather than copied.
    let schema: Value =
        serde_norway::from_str(&std::fs::read_to_string(&schema_path).expect("read schema"))
            .expect("the drafted response schema parses as YAML");
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
        stdout.contains("evidencectl source suggest --openapi"),
        "the equivalent command belongs on stdout: {stdout}"
    );
    // The reproduce line is pasted into a shell, so a pointer carrying `*` is
    // quoted rather than left for the shell to expand.
    assert!(
        stdout.contains("--select '/records/*/trackingId'"),
        "the equivalent command must reproduce the selection, quoted: {stdout}"
    );

    // OpenAPI cannot establish governed source policy. The report must make
    // that boundary visible instead of presenting generated defaults.
    assert!(
        stdout.contains("source origin, posture, authentication, selector bindings"),
        "the report must name the omitted decisions: {stdout}"
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
        stderr_of(&repeat).contains("refusing to overwrite"),
        "unexpected refusal message: {}",
        stderr_of(&repeat)
    );
}

#[test]
fn prints_the_draft_without_a_project_and_writes_nothing() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let project = scaffold(workspace.path());
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
        "--- schemas/source-c-response.schema.yaml ---",
        "--- adapters/source-c-extract.rhai ---",
        "--- schemas/source-c-facts.schema.yaml ---",
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
#[cfg(unix)]
#[test]
fn reports_the_check_classification_when_a_runtime_binary_is_supplied() {
    use std::os::unix::fs::PermissionsExt as _;

    let workspace = tempfile::tempdir().expect("tempdir");
    let openapi = write(workspace.path(), "records.openapi.yaml", OPENAPI_DOCUMENT);
    let project = scaffold(workspace.path());

    let stub = workspace.path().join("evidence");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf 'evidence: runtime signing initialization failed\\n' >&2\nexit 1\n",
    )
    .expect("write stub runtime");
    let mut permissions = std::fs::metadata(&stub).expect("stat stub").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&stub, permissions).expect("chmod stub");

    let output = evidencectl(&[
        "source".to_owned(),
        "suggest".to_owned(),
        "--openapi".to_owned(),
        path_argument(&openapi),
        "--operation".to_owned(),
        "GET /records".to_owned(),
        "--select".to_owned(),
        "/records/*/status".to_owned(),
        "--source-id".to_owned(),
        "source-d".to_owned(),
        "--project".to_owned(),
        path_argument(&project),
        "--evidence-bin".to_owned(),
        path_argument(&stub),
    ]);
    assert!(
        output.status.success(),
        "an accepted bundle must not fail the draft: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("bundle accepted; deployment secrets not provisioned yet"),
        "unexpected check report: {stdout}"
    );
}

fn evidencectl(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

/// Create the only precondition `source suggest --project` requires: an
/// existing project directory. `new` is tested separately and now owns the
/// OpenAPI path itself.
fn scaffold(root: &Path) -> PathBuf {
    let project = root.join("project");
    std::fs::create_dir(&project).expect("project directory");
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
