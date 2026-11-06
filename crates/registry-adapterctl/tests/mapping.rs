// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl mapping check | generate | preview` and
//! the `adapter.mapping.script-drift` warning that `adapterctl check` and
//! `adapterctl job check` raise for a generated script that no longer matches
//! its model.

use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://registry.example/schemas/person/1/schema.json",
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {"id": {"type": "string"}, "kind": {"type": "string"}},
      "required": ["id", "kind"],
      "additionalProperties": false
    },
    "household": {
      "type": "object",
      "properties": {"size": {"type": "integer"}},
      "required": ["size"],
      "additionalProperties": false
    }
  },
  "required": ["source"],
  "additionalProperties": false
}"#;

fn model_text(target: &str, mode: Option<&str>, script: &str, entrypoint: &str) -> String {
    let mode = mode
        .map(|mode| format!("  ingestionMode: {mode}\n"))
        .unwrap_or_default();
    format!(
        "apiVersion: id.registrystack.org/formats/adapter/mapping/v1alpha1\n\
         kind: AdapterMapping\n\
         mapping:\n  id: person-registration\n  target: {target}\n  \
         targetSchema: schemas/person.schema.json\n  script: {script}\n  \
         entrypoint: {entrypoint}\n{mode}\
         assignments:\n  \
         - target: source.id\n    from: id\n  \
         - target: source.kind\n    constant: person\n  \
         - target: household.size\n    from: size\n    convert: integer\n"
    )
}

/// A directory holding a schema and one model per target the tests use.
fn workspace() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("schemas")).unwrap();
    std::fs::write(root.path().join("schemas/person.schema.json"), SCHEMA).unwrap();
    std::fs::write(
        root.path().join("person.mapping.yaml"),
        model_text(
            "consultation",
            None,
            "scripts/person.rhai",
            "project_person",
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("ingest.mapping.yaml"),
        model_text(
            "ingestion",
            Some("proposal"),
            "scripts/ingest.rhai",
            "ingest_person",
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("immediate.mapping.yaml"),
        model_text(
            "ingestion",
            Some("immediate"),
            "scripts/immediate.rhai",
            "ingest_now",
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("request.mapping.yaml"),
        model_text(
            "source-request",
            None,
            "scripts/request.rhai",
            "build_request",
        ),
    )
    .unwrap();
    root
}

fn path(root: &tempfile::TempDir, name: &str) -> String {
    root.path().join(name).to_str().unwrap().to_owned()
}

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
    assert_eq!(
        exit == ExitCode::SUCCESS,
        report["ok"] == json!(true),
        "ok must track the exit code: {report}"
    );
    let text = String::from_utf8_lossy(&stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(3)
        .collect::<Vec<_>>();
    assert_eq!(head, ["ok", "command", "status"], "{text}");
    (exit, report, stderr)
}

fn run_human(arguments: &[&str]) -> (ExitCode, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![OsString::from("adapterctl")];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    (
        exit,
        String::from_utf8_lossy(&stdout).into_owned() + &String::from_utf8_lossy(&stderr),
    )
}

fn codes(report: &Value) -> Vec<String> {
    report["diagnostics"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|d| d["code"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn assert_refused(exit: ExitCode, report: &Value, code: &str) {
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["ok"], false, "{report}");
    assert!(codes(report).iter().any(|c| c == code), "{code}: {report}");
}

fn write_input(root: &tempfile::TempDir, name: &str, text: &str) -> String {
    std::fs::write(root.path().join(name), text).unwrap();
    path(root, name)
}

// --- mapping check ---------------------------------------------------------

#[test]
fn check_accepts_a_valid_model() {
    let root = workspace();
    let (exit, report, stderr) =
        run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty());
    assert_eq!(report["command"], "mapping check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["target"], "consultation");
    assert_eq!(report["assignments"], 3);
    assert_eq!(report["diagnostics"], json!([]));
}

#[test]
fn check_reports_the_target_tree_the_checker_reads() {
    let root = workspace();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        report["targetTree"],
        json!([
            {"path": "household", "key": "household", "type": "object", "required": false,
             "mappable": false, "children": [
                {"path": "household.size", "key": "size", "type": "integer", "required": true,
                 "mappable": true, "conversions": ["none", "integer"]}
             ]},
            {"path": "source", "key": "source", "type": "object", "required": true,
             "mappable": false, "children": [
                {"path": "source.id", "key": "id", "type": "string", "required": true,
                 "mappable": true, "conversions": ["none", "text", "date"]},
                {"path": "source.kind", "key": "kind", "type": "string", "required": true,
                 "mappable": true, "conversions": ["none", "text", "date"]}
             ]}
        ]),
        "{report}"
    );
}

#[test]
fn check_names_the_target_field_on_findings_about_one_field() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    // Leave source.kind unmapped and give household.size a conversion its
    // integer target refuses.
    let text = text
        .replace("  - target: source.kind\n    constant: person\n", "")
        .replace("convert: integer", "convert: date");
    std::fs::write(&model, text).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    let target_of = |code: &str| {
        let found: Vec<&Value> = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["code"] == code)
            .collect();
        assert_eq!(found.len(), 1, "{code}: {report}");
        found[0]["target"].clone()
    };
    assert_eq!(
        target_of("adapter.mapping.required-unmapped"),
        json!("source.kind")
    );
    assert_eq!(
        target_of("adapter.mapping.conversion-target-mismatch"),
        json!("household.size")
    );
    // The message text is unchanged and the tree is still reported.
    let unmapped = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "adapter.mapping.required-unmapped")
        .unwrap();
    assert_eq!(unmapped["path"], "/assignments", "{report}");
    assert!(unmapped["message"]
        .as_str()
        .unwrap()
        .contains("source.kind"));
    assert!(report["targetTree"].is_array(), "{report}");
}

#[test]
fn check_names_no_target_on_findings_about_the_model_as_a_whole() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("scripts/person.rhai", "scripts/person.txt"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_refused(exit, &report, "adapter.mapping.path-invalid");
    for diagnostic in report["diagnostics"].as_array().unwrap() {
        assert!(diagnostic.get("target").is_none(), "{diagnostic}");
    }
}

#[test]
fn check_reports_no_target_tree_when_the_schema_root_is_unsupported() {
    let root = workspace();
    std::fs::write(
        root.path().join("schemas/person.schema.json"),
        r#"{"type": "array"}"#,
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_refused(exit, &report, "adapter.mapping.schema-unsupported");
    assert!(report.get("targetTree").is_none(), "{report}");
}

/// The target schema's title is display text for tools; it sits beside the
/// target tree and is absent when the schema has none.
#[test]
fn check_reports_the_title_of_the_target_schema_root() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(report.get("targetTitle").is_none(), "{report}");

    let titled = SCHEMA.replacen(
        "\"type\": \"object\",",
        "\"title\": \"Register a person\",\n  \"type\": \"object\",",
        1,
    );
    assert_ne!(titled, SCHEMA);
    std::fs::write(root.path().join("schemas/person.schema.json"), &titled).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["targetTitle"], "Register a person", "{report}");
    assert!(report["targetTree"].is_array(), "{report}");
    // Like the tree, the title is for tools; the text form leaves it out.
    let (_, text) = run_human(&["mapping", "check", &model]);
    assert!(!text.contains("targetTitle"), "{text}");
    assert!(!text.contains("Register a person"), "{text}");

    // Only the root's title counts: a nested one names a field, and an
    // empty one names nothing.
    for schema in [
        SCHEMA.replacen("\"source\": {", "\"source\": {\"title\": \"Nested\",", 1),
        titled.replacen("\"Register a person\"", "\"\"", 1),
    ] {
        std::fs::write(root.path().join("schemas/person.schema.json"), schema).unwrap();
        let (exit, report, _) = run_json(&["mapping", "check", &model]);
        assert_eq!(exit, ExitCode::SUCCESS, "{report}");
        assert!(report.get("targetTitle").is_none(), "{report}");
    }

    // A title that is not text makes the schema invalid, and the report
    // shows none.
    let not_text = titled.replacen("\"Register a person\"", "7", 1);
    std::fs::write(root.path().join("schemas/person.schema.json"), not_text).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(report.get("targetTitle").is_none(), "{report}");
}

/// A refusal still carries the title, as it carries the tree.
#[test]
fn check_reports_the_title_when_the_model_is_refused() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("household.size", "household.sizes")).unwrap();
    let titled = SCHEMA.replacen(
        "\"type\": \"object\",",
        "\"title\": \"Register a person\",\n  \"type\": \"object\",",
        1,
    );
    std::fs::write(root.path().join("schemas/person.schema.json"), titled).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["targetTitle"], "Register a person", "{report}");
}

/// No schema, no title: an unreadable schema reports neither member.
#[test]
fn check_reports_no_title_when_the_schema_cannot_be_read() {
    let root = workspace();
    std::fs::write(
        root.path().join("schemas/person.schema.json"),
        r#"{"title": "Hidden", "#,
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(report.get("targetTitle").is_none(), "{report}");
}

#[test]
fn check_human_output_names_the_verdict() {
    let root = workspace();
    let (exit, text) = run_human(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{text}");
    assert!(text.contains("Mapping check passed."), "{text}");
    // The target tree is for tools; the text form leaves it to `--format json`.
    assert!(!text.contains("targetTree"), "{text}");
}

#[test]
fn check_refuses_an_assignment_the_schema_does_not_declare() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("household.size", "household.sizes")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["ok"], false);
    assert!(
        codes(&report)
            .iter()
            .all(|c| c.starts_with("adapter.mapping.")),
        "{report}"
    );
    assert!(!codes(&report).is_empty());
    let unknown = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "adapter.mapping.target-unknown")
        .expect("a target-unknown finding");
    let message = unknown["message"].as_str().unwrap();
    assert!(
        message.contains("household.sizes") && message.contains("schemas/person.schema.json"),
        "{message}"
    );
}

/// `mapping check` applies the acceptance the runtime applies when it
/// compiles the script, so a schema preview would refuse fails here first.
#[test]
fn check_refuses_a_target_schema_the_runtime_would_not_compile() {
    for (edit, rule, action) in [
        (
            (
                "https://registry.example/schemas/person/1/schema.json",
                "urn:person",
            ),
            "versioned absolute HTTPS $id",
            "https://example.org/schemas/<name>/1/schema.json",
        ),
        (
            (
                "\"required\": [\"source\"],\n  \"additionalProperties\": false",
                "\"required\": [\"source\"]",
            ),
            "closed object",
            "\"additionalProperties\": false",
        ),
    ] {
        let root = workspace();
        let schema = root.path().join("schemas/person.schema.json");
        let text = std::fs::read_to_string(&schema).unwrap();
        assert!(text.contains(edit.0), "{}", edit.0);
        std::fs::write(&schema, text.replace(edit.0, edit.1)).unwrap();
        let model = path(&root, "person.mapping.yaml");
        let (exit, report, _) = run_json(&["mapping", "check", &model]);
        assert_refused(exit, &report, "adapterctl.mapping-schema-not-public");
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["path"], "/mapping/targetSchema", "{report}");
        let message = finding["message"].as_str().unwrap();
        assert!(
            message.contains("schemas/person.schema.json") && message.contains(rule),
            "{message}"
        );
        let next = finding["suggestedAction"].as_str().unwrap();
        assert!(next.contains(action), "{next}");
        let (exit, report, _) = run_json(&["mapping", "generate", &model]);
        assert_refused(exit, &report, "adapterctl.mapping-schema-not-public");
        assert!(!root.path().join("scripts").exists());
    }
}

#[test]
fn check_refuses_a_missing_target_schema_with_a_command_code() {
    let root = workspace();
    std::fs::remove_file(root.path().join("schemas/person.schema.json")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_refused(exit, &report, "adapterctl.mapping-schema-unreadable");
}

#[test]
fn check_refuses_a_wrong_kind_through_the_shared_reader() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("kind: AdapterMapping", "kind: AdapterJob"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(
        codes(&report).iter().any(|c| c.starts_with("config.")),
        "{report}"
    );
}

#[test]
fn check_of_a_missing_model_is_an_operational_failure() {
    let root = workspace();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "absent.mapping.yaml")]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "adapterctl.io-failure");
}

// --- mapping generate ------------------------------------------------------

#[test]
fn generate_writes_the_script_and_reports_the_next_step() {
    let root = workspace();
    let (exit, report, stderr) =
        run_json(&["mapping", "generate", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty());
    assert_eq!(report["command"], "mapping generate");
    assert_eq!(report["changed"], true);
    let script = std::fs::read_to_string(root.path().join("scripts/person.rhai")).unwrap();
    assert!(script.starts_with("// Generated by adapterctl"), "{script}");
    assert!(script.contains("fn project_person(source)"), "{script}");
    let digest = report["scriptDigest"].as_str().unwrap();
    assert_eq!(
        digest,
        registry_platform_config::sha256_uri(script.as_bytes())
    );
    assert!(report["nextStep"]
        .as_str()
        .unwrap()
        .contains("adapterctl project lock"));
    assert!(!root.path().join("scripts/.person.rhai.tmp").exists());
}

#[test]
fn generate_for_ingestion_points_at_the_job_digest() {
    let root = workspace();
    let (exit, report, _) = run_json(&["mapping", "generate", &path(&root, "ingest.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let next = report["nextStep"].as_str().unwrap();
    assert!(next.contains("adapterctl job lock"), "{next}");
    assert!(!next.contains("sha256:"), "{next}");
    assert!(report["scriptDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let script = std::fs::read_to_string(root.path().join("scripts/ingest.rhai")).unwrap();
    assert!(
        script.contains("fn ingest_person_input(source)"),
        "{script}"
    );
}

/// The human form says what was written and the one next step; the digests
/// and the existed flag stay in `--format json`.
#[test]
fn generate_human_output_is_the_verdict_and_one_next_step() {
    let root = workspace();
    for (model, next) in [
        ("person.mapping.yaml", "Next: Run adapterctl project lock"),
        ("ingest.mapping.yaml", "Next: Run adapterctl job lock"),
    ] {
        let (exit, text) = run_human(&["mapping", "generate", &path(&root, model)]);
        assert_eq!(exit, ExitCode::SUCCESS, "{text}");
        assert!(text.contains("Generated script written."), "{text}");
        assert_eq!(text.matches("Next: ").count(), 1, "{text}");
        assert!(text.contains(next), "{text}");
        for absent in [
            "modelDigest",
            "scriptDigest",
            "existed",
            "nextStep",
            "sha256:",
        ] {
            assert!(!text.contains(absent), "{absent}: {text}");
        }
    }
}

#[test]
fn generate_has_no_deny_warnings_flag() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let (exit, _, _) = run_json(&["mapping", "generate", &model, "--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(2));
    assert!(!root.path().join("scripts").exists());
}

#[test]
fn generate_twice_reports_unchanged_with_identical_bytes() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let (_, first, _) = run_json(&["mapping", "generate", &model]);
    let bytes = std::fs::read(root.path().join("scripts/person.rhai")).unwrap();
    let (exit, second, _) = run_json(&["mapping", "generate", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{second}");
    assert_eq!(second["changed"], false);
    assert_eq!(second["scriptDigest"], first["scriptDigest"]);
    assert_eq!(
        std::fs::read(root.path().join("scripts/person.rhai")).unwrap(),
        bytes
    );
    let (_, text) = run_human(&["mapping", "generate", &model]);
    assert!(text.contains("already current"), "{text}");
}

#[test]
fn generate_refuses_to_overwrite_a_handwritten_script_unless_forced() {
    let root = workspace();
    std::fs::create_dir_all(root.path().join("scripts")).unwrap();
    let script = root.path().join("scripts/person.rhai");
    std::fs::write(&script, "fn project_person(source) { #{} }\n").unwrap();
    let model = path(&root, "person.mapping.yaml");
    let (exit, report, _) = run_json(&["mapping", "generate", &model]);
    assert_refused(exit, &report, "adapterctl.mapping-script-handwritten");
    assert_eq!(
        std::fs::read_to_string(&script).unwrap(),
        "fn project_person(source) { #{} }\n"
    );
    let (exit, report, _) = run_json(&["mapping", "generate", &model, "--force"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(std::fs::read_to_string(&script)
        .unwrap()
        .starts_with("// Generated by adapterctl"));
}

#[test]
fn generate_overwrites_a_previously_generated_script_after_a_hand_edit() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    run_json(&["mapping", "generate", &model]);
    let script = root.path().join("scripts/person.rhai");
    let generated = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{generated}// hand edit\n")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["changed"], true);
    assert_eq!(std::fs::read_to_string(&script).unwrap(), generated);
}

#[test]
fn generate_writes_nothing_when_the_model_is_refused() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("household.size", "household.sizes")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", &model]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(!root.path().join("scripts").exists());
}

// --- mapping preview -------------------------------------------------------

#[test]
fn preview_reports_an_accepted_and_a_refused_consultation_input() {
    let root = workspace();
    let good = write_input(&root, "good.json", r#"{"id": "501", "size": "5"}"#);
    let bad = write_input(&root, "bad.json", r#"{"size": "5"}"#);
    let (exit, report, stderr) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &good,
        "--input",
        &bad,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(stderr.is_empty());
    assert_eq!(report["command"], "mapping preview");
    assert_eq!(report["accepted"], 1);
    assert_eq!(report["refused"], 1);
    assert_eq!(report["results"][0]["outcome"], "accepted");
    assert_eq!(
        report["results"][0]["output"],
        json!({"source": {"id": "501", "kind": "person"}, "household": {"size": 5}})
    );
    assert_eq!(report["results"][1]["outcome"], "refused");
    assert_eq!(report["results"][1]["failure"], "mapping.missing");
    assert_eq!(report["results"][1]["field"], "source.id");
    assert!(
        !root.path().join("scripts").exists(),
        "preview writes nothing"
    );
}

/// Each refusal the generated script raises names its category and the
/// target field, never the source value.
#[test]
fn preview_names_the_failing_field_without_the_value() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    let keyed = root.path().join("keyed.mapping.yaml");
    std::fs::write(
        &keyed,
        text.replace("from: size", "from: 'items[k = \"size\"].v'")
            .replace("scripts/person.rhai", "scripts/keyed.rhai"),
    )
    .unwrap();
    let missing = write_input(&root, "missing.json", r#"{"size": "SECRET-ONE"}"#);
    let conversion = write_input(
        &root,
        "conversion.json",
        r#"{"id": "1", "size": "SECRET-TWO"}"#,
    );
    let duplicate = write_input(
        &root,
        "duplicate.json",
        r#"{"id": "1", "items": [{"k": "size", "v": "SECRET-THREE"}, {"k": "size", "v": "4"}]}"#,
    );
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &model,
        "--input",
        &missing,
        "--input",
        &conversion,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let named = |report: &Value, index: usize| {
        (
            report["results"][index]["failure"]
                .as_str()
                .unwrap()
                .to_owned(),
            report["results"][index]["field"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
    };
    assert_eq!(
        named(&report, 0),
        ("mapping.missing".into(), "source.id".into())
    );
    assert_eq!(
        named(&report, 1),
        ("mapping.conversion".into(), "household.size".into())
    );
    let (_, human) = run_human(&[
        "mapping",
        "preview",
        &model,
        "--input",
        &missing,
        "--input",
        &conversion,
    ]);
    let keyed = keyed.to_str().unwrap();
    let (exit, keyed_report, _) = run_json(&["mapping", "preview", keyed, "--input", &duplicate]);
    assert_eq!(exit, ExitCode::SUCCESS, "{keyed_report}");
    assert_eq!(
        named(&keyed_report, 0),
        ("mapping.duplicate".into(), "household.size".into())
    );
    let printed = format!("{report}{keyed_report}{human}");
    assert!(!printed.contains("SECRET"), "{printed}");
}

/// A quoted key or filter literal reaches a source key or value outside
/// printable ASCII, and an escaped quote reaches a key holding one. Keys are
/// compared byte for byte, so the decomposed spelling of an accented key is a
/// different key.
#[test]
fn preview_reaches_source_keys_and_values_outside_printable_ascii() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    let unicode = root.path().join("unicode.mapping.yaml");
    std::fs::write(
        &unicode,
        text.replace("from: id", "from: '\"pr\u{e9}nom\"'")
            .replace(
                "from: size",
                "from: 'places[name = \"Saint-\u{c9}tienne \\\"Nord\\\"\"].code'",
            )
            .replace("scripts/person.rhai", "scripts/unicode.rhai"),
    )
    .unwrap();
    let unicode = unicode.to_str().unwrap();
    let composed = write_input(
        &root,
        "composed.json",
        r#"{"pr\u00e9nom": "Am\u00e9lie", "places": [
            {"name": "Saint-\u00c9tienne \"Nord\"", "code": "42"},
            {"name": "Saint-Etienne", "code": "7"}]}"#,
    );
    let decomposed = write_input(
        &root,
        "decomposed.json",
        r#"{"pre\u0301nom": "Am\u00e9lie", "places": []}"#,
    );
    let (exit, report, _) = run_json(&["mapping", "check", unicode]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        unicode,
        "--input",
        &composed,
        "--input",
        &decomposed,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        report["results"][0]["output"],
        json!({"source": {"id": "Am\u{e9}lie", "kind": "person"}, "household": {"size": 42}}),
        "{report}"
    );
    assert_eq!(report["results"][1]["outcome"], "refused", "{report}");
    assert_eq!(
        report["results"][1]["failure"], "mapping.missing",
        "{report}"
    );
    assert_eq!(report["results"][1]["field"], "source.id", "{report}");
}

/// The human form is one line per input: its outcome, and for a refusal the
/// failure and the field it names.
#[test]
fn preview_human_output_is_one_line_per_input() {
    let root = workspace();
    let good = write_input(&root, "good.json", r#"{"id": "501", "size": "5"}"#);
    let bad = write_input(&root, "bad.json", r#"{"size": "5"}"#);
    let broken = write_input(&root, "broken.json", "{ not: [valid");
    let (exit, text) = run_human(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &good,
        "--input",
        &bad,
        "--input",
        &broken,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{text}");
    assert!(text.contains(&format!("{good}  accepted\n")), "{text}");
    assert!(
        text.contains(&format!("{bad}  refused  mapping.missing source.id\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("{broken}  refused  input-unreadable\n")),
        "{text}"
    );
    assert!(!text.contains("results:"), "{text}");
}

#[test]
fn preview_help_says_the_script_is_generated_in_memory() {
    let (exit, text) = run_human(&["mapping", "preview", "--help"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{text}");
    assert!(text.contains("in memory"), "{text}");
}

#[test]
fn preview_accepts_a_yaml_input() {
    let root = workspace();
    let good = write_input(&root, "good.yaml", "id: \"501\"\nsize: \"5\"\n");
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &good,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["results"][0]["outcome"], "accepted", "{report}");
}

#[test]
fn preview_of_a_refused_input_never_echoes_the_value() {
    let root = workspace();
    let bad = write_input(
        &root,
        "bad.json",
        r#"{"id": "501", "size": "SECRET-MARKER"}"#,
    );
    let (_, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &bad,
    ]);
    assert_eq!(report["results"][0]["outcome"], "refused");
    assert!(!report.to_string().contains("SECRET-MARKER"), "{report}");
}

#[test]
fn preview_of_ingestion_wraps_a_proposal_and_leaves_immediate_bare() {
    let root = workspace();
    let good = write_input(&root, "good.json", r#"{"id": "501", "size": "5"}"#);
    let bad = write_input(&root, "bad.json", r#"{"size": "5"}"#);
    let source = json!({"source": {"id": "501", "kind": "person"}, "household": {"size": 5}});

    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "ingest.mapping.yaml"),
        "--input",
        &good,
        "--input",
        &bad,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        report["results"][0]["output"],
        json!({"startInput": {"input": source}, "submitBody": {}})
    );
    assert_eq!(report["results"][1]["outcome"], "refused");

    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "immediate.mapping.yaml"),
        "--input",
        &good,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["results"][0]["output"], source);
}

#[test]
fn preview_refuses_a_source_request_model() {
    let root = workspace();
    let good = write_input(&root, "good.json", r#"{"id": "501"}"#);
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "request.mapping.yaml"),
        "--input",
        &good,
    ]);
    assert_refused(exit, &report, "adapterctl.mapping-preview-unsupported");
}

#[test]
fn preview_marks_an_unreadable_input_without_failing_the_run() {
    let root = workspace();
    let broken = write_input(&root, "broken.json", "{ not: [valid");
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &broken,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["results"][0]["failure"], "input-unreadable");
}

#[test]
fn preview_of_a_missing_input_is_an_operational_failure() {
    let root = workspace();
    let (exit, report, _) = run_json(&[
        "mapping",
        "preview",
        &path(&root, "person.mapping.yaml"),
        "--input",
        &path(&root, "none.json"),
    ]);
    assert_eq!(exit, ExitCode::from(3), "{report}");
}

// --- drift in check --------------------------------------------------------

/// A copy of the minimal project with a generated script inventoried, plus
/// the model that generates it.
fn project_with_generated_script() -> (tempfile::TempDir, String, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal");
    copy_tree(&source, root.path());
    std::fs::create_dir_all(root.path().join("schemas")).unwrap();
    std::fs::write(root.path().join("schemas/person.schema.json"), SCHEMA).unwrap();
    std::fs::write(
        root.path().join("gen.mapping.yaml"),
        model_text("consultation", None, "scripts/gen.rhai", "project_person"),
    )
    .unwrap();
    let model = root.path().join("gen.mapping.yaml");
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let project = root.path().join("project.yaml");
    let mut text = std::fs::read_to_string(&project).unwrap();
    text.push_str(&format!(
        "artifacts:\n  scripts:\n    - id: gen\n      file: scripts/gen.rhai\n      digest: {}\n",
        report["scriptDigest"].as_str().unwrap()
    ));
    std::fs::write(&project, text).unwrap();
    (root, project.to_str().unwrap().to_owned(), model)
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn drift_warnings(report: &Value) -> Vec<&Value> {
    report["diagnostics"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|d| d["code"] == "adapter.mapping.script-drift")
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn check_raises_no_drift_warning_for_a_current_generated_script() {
    let (_root, project, _) = project_with_generated_script();
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_a_generated_script_is_hand_edited() {
    let (root, project, _) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{text}// hand edit\n")).unwrap();
    // Re-pin so the digest check is not the finding under test.
    let (exit, report, _) = run_json(&["project", "lock", root.path().to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = drift_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["severity"], "warning");
    let message = warnings[0]["message"].as_str().unwrap();
    assert!(
        message.contains("gen.rhai") && message.contains("gen.mapping.yaml"),
        "{message}"
    );
    let next = warnings[0]["suggestedAction"].as_str().unwrap();
    assert!(
        next.contains("model changed since generation")
            && next.contains("hand-edited")
            && next.contains("adapterctl mapping generate"),
        "{next}"
    );
    let (exit, report, _) = run_json(&["check", &project, "--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(!drift_warnings(&report).is_empty());
}

#[test]
fn check_warns_when_the_model_changes_after_generation() {
    let (root, project, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        format!("{text}  - target: household.size\n    constant: 1\n"),
    )
    .unwrap();
    let (_, report, _) = run_json(&["check", &project]);
    // The edited model repeats a target, so it is also invalid: both a
    // changed and an invalid model warn.
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
    let _ = root;
}

#[test]
fn mapping_check_deny_warnings_keeps_the_report_members() {
    let (_root, _, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("constant: person", "constant: human")).unwrap();
    let (exit, report, _) = run_json(&[
        "mapping",
        "check",
        model.to_str().unwrap(),
        "--deny-warnings",
    ]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(report["ok"], false, "{report}");
    assert!(!drift_warnings(&report).is_empty(), "{report}");
    assert!(report["targetTree"].is_array(), "{report}");
}

/// `mapping check` names why a generated script drifted: the model's digest
/// no longer matches the header, or the script differs from a model whose
/// digest still matches.
fn mapping_check_drift(model: &Path) -> Value {
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = drift_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    warnings[0].clone()
}

#[test]
fn mapping_check_names_a_hand_edited_script_as_differing_bytes() {
    let (root, _, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{text}// hand edit\n")).unwrap();
    let warning = mapping_check_drift(&model);
    assert_eq!(warning["cause"], "script-differs");
    let message = warning["message"].as_str().unwrap();
    assert!(
        message.contains("the model's digest still matches"),
        "{message}"
    );
}

#[test]
fn mapping_check_names_an_edited_header_as_differing_bytes() {
    let (root, _, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    let lines: Vec<&str> = text.split('\n').collect();
    let edited = [&lines[..1], &["// edited header line"], &lines[2..]].concat();
    std::fs::write(&script, edited.join("\n")).unwrap();
    assert_eq!(mapping_check_drift(&model)["cause"], "script-differs");
}

#[test]
fn mapping_check_names_a_changed_model_as_the_cause() {
    let (_root, _, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("constant: person", "constant: human")).unwrap();
    let warning = mapping_check_drift(&model);
    assert_eq!(warning["cause"], "model-changed");
    let message = warning["message"].as_str().unwrap();
    assert!(message.contains("the model changed since"), "{message}");
}

/// The header pins the model's meaning, not its layout: a byte order mark,
/// CRLF line endings, comments and document markers leave the script current.
#[test]
fn check_raises_no_drift_warning_when_only_the_model_layout_changes() {
    let (_root, project, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    let relaid = format!(
        "\u{feff}---\r\n# a reviewer's note\r\n{}...\r\n",
        text.replace('\n', "\r\n")
    );
    std::fs::write(&model, relaid).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(drift_warnings(&report).is_empty(), "{report}");
    let (exit, report, _) = run_json(&["check", &project, "--deny-warnings"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_the_model_is_missing() {
    let (_root, project, model) = project_with_generated_script();
    std::fs::remove_file(&model).unwrap();
    let (_, report, _) = run_json(&["check", &project]);
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
}

#[test]
fn check_raises_no_drift_warning_for_a_handwritten_script() {
    let (root, project, _) = project_with_generated_script();
    std::fs::write(
        root.path().join("scripts/gen.rhai"),
        "// handwritten\nfn project_person(source) { #{} }\n",
    )
    .unwrap();
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    let (_, report, _) = run_json(&["check", &project]);
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_a_header_names_a_model_outside_the_project() {
    let (root, project, _) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    let escaped = text.replace("model=../gen.mapping.yaml", "model=../../gen.mapping.yaml");
    assert_ne!(text, escaped);
    std::fs::write(&script, escaped).unwrap();
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    let (_, report, _) = run_json(&["check", &project]);
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
}

fn lock_and_check(root: &tempfile::TempDir, project: &str) -> Value {
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    run_json(&["check", project]).1
}

fn only_drift_message(report: &Value) -> String {
    let warnings = drift_warnings(report);
    assert_eq!(warnings.len(), 1, "{report}");
    warnings[0]["message"].as_str().unwrap().to_owned()
}

#[test]
fn check_warns_when_the_generated_header_is_malformed() {
    for edit in [
        |text: &str| text.replacen("digest=", "digst=", 1),
        |text: &str| text.replace('\n', "\r\n"),
    ] {
        let (root, project, _) = project_with_generated_script();
        let script = root.path().join("scripts/gen.rhai");
        let text = std::fs::read_to_string(&script).unwrap();
        let edited = edit(&text);
        assert_ne!(text, edited);
        std::fs::write(&script, edited).unwrap();
        let report = lock_and_check(&root, &project);
        let message = only_drift_message(&report);
        assert!(message.contains("malformed"), "{message}");
    }
}

#[test]
fn generate_regenerates_a_script_whose_header_was_edited() {
    let (root, _, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, text.replacen("digest=", "digst=", 1)).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(std::fs::read_to_string(&script).unwrap(), text);
}

#[test]
fn check_accepts_a_generated_script_in_a_nested_directory() {
    let (root, project, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("scripts/gen.rhai", "scripts/deeper/gen.rhai"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let script = std::fs::read_to_string(root.path().join("scripts/deeper/gen.rhai")).unwrap();
    assert!(script.contains("model=../../gen.mapping.yaml"), "{script}");
    let project_text = std::fs::read_to_string(&project).unwrap();
    std::fs::write(
        &project,
        project_text.replace("scripts/gen.rhai", "scripts/deeper/gen.rhai"),
    )
    .unwrap();
    let report = lock_and_check(&root, &project);
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_the_header_reference_is_deeper_or_shallower_than_the_script() {
    for reference in ["../../gen.mapping.yaml", "gen.mapping.yaml"] {
        let (root, project, _) = project_with_generated_script();
        // A copy beside the script keeps the shallow reference resolvable.
        std::fs::copy(
            root.path().join("gen.mapping.yaml"),
            root.path().join("scripts/gen.mapping.yaml"),
        )
        .unwrap();
        let script = root.path().join("scripts/gen.rhai");
        let text = std::fs::read_to_string(&script).unwrap();
        std::fs::write(
            &script,
            text.replace("model=../gen.mapping.yaml", &format!("model={reference}")),
        )
        .unwrap();
        let report = lock_and_check(&root, &project);
        only_drift_message(&report);
    }
}

#[test]
fn generate_refuses_to_overwrite_another_models_script_unless_forced() {
    let root = workspace();
    let first = path(&root, "person.mapping.yaml");
    run_json(&["mapping", "generate", &first]);
    let other = root.path().join("other.mapping.yaml");
    std::fs::write(
        &other,
        model_text(
            "consultation",
            None,
            "scripts/person.rhai",
            "project_person",
        ),
    )
    .unwrap();
    let script = root.path().join("scripts/person.rhai");
    let original = std::fs::read_to_string(&script).unwrap();
    let other = other.to_str().unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", other]);
    assert_refused(exit, &report, "adapterctl.mapping-script-owned");
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("person.mapping.yaml") && message.contains("other.mapping.yaml"),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&script).unwrap(), original);
    let (exit, report, _) = run_json(&["mapping", "generate", other, "--force"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(std::fs::read_to_string(&script)
        .unwrap()
        .contains("model=../other.mapping.yaml"));
}

#[test]
fn generate_regenerates_its_own_script_without_force() {
    let root = workspace();
    let model = path(&root, "person.mapping.yaml");
    run_json(&["mapping", "generate", &model]);
    let (exit, report, _) = run_json(&["mapping", "generate", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
}

#[cfg(unix)]
#[test]
fn generate_through_a_symlink_out_of_the_model_directory_leaves_nothing_behind() {
    let root = workspace();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
    let model = root.path().join("person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("scripts/person.rhai", "link/created/person.rhai"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_ne!(exit, ExitCode::SUCCESS, "{report}");
    assert!(
        std::fs::read_dir(outside.path()).unwrap().next().is_none(),
        "a refused write must create nothing outside the model directory"
    );
}

/// A target schema whose path is clean but whose link resolves outside the
/// model's directory is refused at the member by every command that reads
/// it, and nothing is written through it (CFG-VAL-8).
#[cfg(unix)]
#[test]
fn a_target_schema_linked_outside_the_model_directory_is_refused() {
    let root = workspace();
    let outside = tempfile::tempdir().unwrap();
    let schema = root.path().join("schemas/person.schema.json");
    let moved = outside.path().join("person.schema.json");
    std::fs::rename(&schema, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &schema).unwrap();
    let model = path(&root, "person.mapping.yaml");
    let input = write_input(&root, "good.json", r#"{"id": "501", "size": "5"}"#);
    for arguments in [
        vec!["mapping", "check", model.as_str()],
        vec!["mapping", "generate", model.as_str()],
        vec![
            "mapping",
            "preview",
            model.as_str(),
            "--input",
            input.as_str(),
        ],
    ] {
        let (exit, report, _) = run_json(&arguments);
        assert_refused(exit, &report, "adapterctl.mapping-schema-outside");
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["path"], "/mapping/targetSchema", "{report}");
        let message = finding["message"].as_str().unwrap();
        assert!(
            !message.contains(outside.path().to_str().unwrap()),
            "the finding never names the link's target: {message}"
        );
    }
    assert!(!root.path().join("scripts").exists(), "nothing is written");
}

/// A link that stays inside the model's directory is followed: the same
/// containment the script write and the drift check apply.
#[cfg(unix)]
#[test]
fn a_target_schema_linked_inside_the_model_directory_is_read() {
    let root = workspace();
    std::fs::create_dir_all(root.path().join("shared")).unwrap();
    let schema = root.path().join("schemas/person.schema.json");
    std::fs::rename(&schema, root.path().join("shared/person.schema.json")).unwrap();
    std::os::unix::fs::symlink("../shared/person.schema.json", &schema).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &path(&root, "person.mapping.yaml")]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
}

/// An integer constant beside an enum member it only rounds to is refused by
/// check and by preview alike, before any script runs; an integral float
/// member the integer equals exactly is accepted by check and by the
/// runtime validation preview runs.
#[test]
fn check_and_preview_agree_on_integer_enum_members() {
    let root = workspace();
    let model = root.path().join("person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    let mapped = "  - target: household.size\n    from: size\n    convert: integer\n";
    assert!(text.contains(mapped), "{text}");
    let schema = root.path().join("schemas/person.schema.json");
    let leaf = r#""size": {"type": "integer"}"#;
    assert!(SCHEMA.contains(leaf));
    let input = write_input(&root, "good.json", r#"{"id": "501"}"#);
    let model = path(&root, "person.mapping.yaml");

    std::fs::write(
        root.path().join("person.mapping.yaml"),
        text.replace(
            mapped,
            "  - target: household.size\n    constant: 9007199254740993\n",
        ),
    )
    .unwrap();
    std::fs::write(
        &schema,
        SCHEMA.replace(
            leaf,
            r#""size": {"type": "integer", "enum": [9007199254740992]}"#,
        ),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_refused(exit, &report, "adapter.mapping.conversion-target-mismatch");
    let (exit, report, _) = run_json(&["mapping", "preview", &model, "--input", &input]);
    assert_refused(exit, &report, "adapter.mapping.conversion-target-mismatch");

    std::fs::write(
        root.path().join("person.mapping.yaml"),
        text.replace(mapped, "  - target: household.size\n    constant: 1\n"),
    )
    .unwrap();
    std::fs::write(
        &schema,
        SCHEMA.replace(leaf, r#""size": {"type": "number", "enum": [1.0]}"#),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", &model]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let (exit, report, _) = run_json(&["mapping", "preview", &model, "--input", &input]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["accepted"], 1, "{report}");
    assert_eq!(report["results"][0]["output"]["household"]["size"], 1);
}

/// The model and its script named without a directory, from the model's own
/// directory, write the script beside the model. The child process runs in
/// that directory, so the test never moves this process's working directory.
#[test]
fn generate_of_a_bare_model_file_name_writes_the_script_beside_it() {
    let root = workspace();
    let model = root.path().join("person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("scripts/person.rhai", "person.rhai")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_adapterctl"))
        .current_dir(root.path())
        .args([
            "--format=json",
            "mapping",
            "generate",
            "person.mapping.yaml",
        ])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert!(output.status.success(), "{report}");
    assert_eq!(report["changed"], true, "{report}");
    let script = std::fs::read_to_string(root.path().join("person.rhai")).unwrap();
    assert!(script.contains("person.mapping.yaml"), "{script}");
}

#[test]
fn check_reports_a_model_file_name_that_generate_refuses() {
    let root = workspace();
    let model = root.path().join(".hidden.mapping.yaml");
    std::fs::copy(root.path().join("person.mapping.yaml"), &model).unwrap();
    let model = model.to_str().unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model]);
    assert_refused(exit, &report, "adapter.mapping.header-invalid");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/mapping/script", "{report}");
    let (exit, report, _) = run_json(&["mapping", "generate", model]);
    assert_refused(exit, &report, "adapter.mapping.header-invalid");
}

#[test]
fn check_accepts_a_model_in_a_subdirectory_beside_its_script() {
    let (root, project, _) = project_with_generated_script();
    std::fs::create_dir_all(root.path().join("mappings/schemas")).unwrap();
    std::fs::write(
        root.path().join("mappings/schemas/person.schema.json"),
        SCHEMA,
    )
    .unwrap();
    let model = root.path().join("mappings/x.mapping.yaml");
    std::fs::write(
        &model,
        model_text("consultation", None, "x.rhai", "project_person"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let script = std::fs::read_to_string(root.path().join("mappings/x.rhai")).unwrap();
    assert!(script.contains("model=x.mapping.yaml"), "{script}");
    let project_text = std::fs::read_to_string(&project).unwrap();
    std::fs::write(
        &project,
        project_text.replace("scripts/gen.rhai", "mappings/x.rhai"),
    )
    .unwrap();
    let report = lock_and_check(&root, &project);
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_a_valid_model_changes_after_generation() {
    let (root, project, model) = project_with_generated_script();
    let text = std::fs::read_to_string(&model).unwrap();
    assert!(text.contains("constant: person"));
    std::fs::write(
        &model,
        text.replace("constant: person", "constant: individual"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(
        exit,
        ExitCode::SUCCESS,
        "the edited model is valid: {report}"
    );
    let warnings = drift_warnings(&report);
    assert_eq!(
        warnings.len(),
        1,
        "mapping check sees the stale script: {report}"
    );
    assert_eq!(warnings[0]["path"], "/mapping/script", "{report}");
    let (exit, report, _) = run_json(&[
        "mapping",
        "check",
        model.to_str().unwrap(),
        "--deny-warnings",
    ]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
    let _ = root;
}

// --- mapping check against the script on disk ------------------------------

#[test]
fn mapping_check_is_silent_for_a_current_script() {
    let (_root, _project, model) = project_with_generated_script();
    let (exit, report, _) = run_json(&[
        "mapping",
        "check",
        model.to_str().unwrap(),
        "--deny-warnings",
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["diagnostics"], json!([]), "{report}");
}

#[test]
fn mapping_check_warns_when_its_script_is_hand_edited() {
    let (root, _project, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{text}// hand edit\n")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = drift_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["severity"], "warning", "{report}");
    assert!(
        warnings[0]["message"]
            .as_str()
            .unwrap()
            .contains("gen.rhai"),
        "{report}"
    );
}

#[test]
fn mapping_check_warns_when_its_script_is_handwritten_or_another_models() {
    let (root, _project, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    std::fs::write(&script, "fn project_person(source) { #{} }\n").unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        codes(&report),
        ["adapterctl.mapping-script-handwritten"],
        "{report}"
    );
    assert_eq!(report["diagnostics"][0]["severity"], "warning", "{report}");

    let other = root.path().join("other.mapping.yaml");
    std::fs::copy(&model, &other).unwrap();
    std::fs::remove_file(&script).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", other.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(
        codes(&report),
        ["adapterctl.mapping-script-owned"],
        "{report}"
    );
}

#[cfg(unix)]
#[test]
fn generate_keeps_the_file_mode_of_the_script_it_replaces() {
    use std::os::unix::fs::PermissionsExt;
    let (root, _project, model) = project_with_generated_script();
    let script = root.path().join("scripts/gen.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{text}// hand edit\n")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o640)).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["changed"], true, "{report}");
    let mode = std::fs::metadata(&script).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
}

#[test]
fn check_refuses_a_script_path_without_the_rhai_extension() {
    let root = workspace();
    let model = root.path().join("person.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("scripts/person.rhai", "scripts/person.txt"),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_refused(exit, &report, "adapter.mapping.path-invalid");
}

// --- drift in a pack's scripts ---------------------------------------------

/// A copy of the minimal project whose pack inventories a script generated
/// from a source-request model that sits inside the pack's directory. The
/// pack is repinned, so only the drift check can speak.
fn pack_with_generated_script() -> (tempfile::TempDir, String, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal");
    copy_tree(&source, root.path());
    std::fs::create_dir_all(root.path().join("schemas")).unwrap();
    std::fs::write(root.path().join("schemas/person.schema.json"), SCHEMA).unwrap();
    let model = root.path().join("upstream.mapping.yaml");
    std::fs::write(
        &model,
        model_text(
            "source-request",
            None,
            "scripts/to-upstream.rhai",
            "to_upstream",
        ),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap(), "--force"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let project = root.path().join("project.yaml");
    let (exit, report, _) = run_json(&["project", "lock", root.path().to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    (root, project.to_str().unwrap().to_owned(), model)
}

#[test]
fn check_raises_no_drift_warning_for_a_current_generated_pack_script() {
    let (_root, project, _) = pack_with_generated_script();
    let (exit, report, _) = run_json(&["check", &project, "--deny-warnings"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_a_generated_pack_script_is_hand_edited() {
    let (root, project, _) = pack_with_generated_script();
    let script = root.path().join("scripts/to-upstream.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{text}// hand edit\n")).unwrap();
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    let (exit, report, _) = run_json(&["check", &project]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = drift_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["path"], "/scripts/1", "{report}");
    let message = warnings[0]["message"].as_str().unwrap();
    assert!(message.contains("to-upstream.rhai"), "{message}");
    let (exit, report, _) = run_json(&["check", &project, "--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
}

#[test]
fn check_raises_no_drift_warning_for_a_handwritten_pack_script() {
    let (root, project, _) = pack_with_generated_script();
    std::fs::write(
        root.path().join("scripts/to-upstream.rhai"),
        "// handwritten\nfn to_upstream(source) { #{} }\n",
    )
    .unwrap();
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    let (_, report, _) = run_json(&["check", &project]);
    assert!(drift_warnings(&report).is_empty(), "{report}");
}

#[test]
fn check_warns_when_a_pack_script_header_names_a_model_outside_the_pack() {
    let (root, project, _) = pack_with_generated_script();
    let script = root.path().join("scripts/to-upstream.rhai");
    let text = std::fs::read_to_string(&script).unwrap();
    let escaped = text.replace(
        "model=../upstream.mapping.yaml",
        "model=../../upstream.mapping.yaml",
    );
    assert_ne!(text, escaped);
    std::fs::write(&script, escaped).unwrap();
    run_json(&["project", "lock", root.path().to_str().unwrap()]);
    let (_, report, _) = run_json(&["check", &project]);
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
}

// --- drift in job check ----------------------------------------------------

#[test]
fn job_check_warns_when_the_destination_mapping_drifts_from_its_model() {
    std::env::set_var("KOBO_USERNAME", "check-contracts");
    std::env::set_var("KOBO_PASSWORD", "check-contracts");
    let products = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter");
    let root = tempfile::tempdir().unwrap();
    copy_tree(&products.join("examples/kobotoolbox-job"), root.path());
    std::fs::create_dir_all(root.path().join("schemas")).unwrap();
    std::fs::write(root.path().join("schemas/person.schema.json"), SCHEMA).unwrap();
    let model = root.path().join("register.mapping.yaml");
    std::fs::write(
        &model,
        model_text(
            "ingestion",
            Some("proposal"),
            "mappings/register-household.rhai",
            "map_submission",
        ),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap(), "--force"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let job = root.path().join("job.yaml");
    let text = std::fs::read_to_string(&job).unwrap();
    let old = "sha256:6b7f1cbbccd57459e15f5ece6282b3ca96946f0525759adcf6acbcc925496da6";
    assert!(text.contains(old));
    std::fs::write(
        &job,
        text.replace(old, report["scriptDigest"].as_str().unwrap()),
    )
    .unwrap();

    let pack = products.join("packs/kobotoolbox/pack.yaml");
    let argument = |name: &str| root.path().join(name).to_str().unwrap().to_owned();
    let check = |extra: &[&str]| {
        let (pack, job, runtime, profile, project) = (
            pack.to_str().unwrap().to_owned(),
            argument("job.yaml"),
            argument("job-runtime.example.yaml"),
            argument("profile.yaml"),
            argument("project.yaml"),
        );
        let mut arguments = vec![
            "job",
            "check",
            pack.as_str(),
            job.as_str(),
            "--runtime",
            runtime.as_str(),
            "--profile",
            profile.as_str(),
            "--project",
            project.as_str(),
        ];
        arguments.extend_from_slice(extra);
        run_json(&arguments)
    };
    let (exit, report, _) = check(&[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(drift_warnings(&report).is_empty(), "{report}");

    // Edit the model only: the pinned script still matches the job digest,
    // so the compile passes and only the drift warning speaks.
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("constant: person", "constant: individual"),
    )
    .unwrap();
    let (exit, report, _) = check(&[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
    let (exit, report, _) = check(&["--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");

    // The human form prints the same warning.
    let (pack, job, runtime, profile, project) = (
        pack.to_str().unwrap().to_owned(),
        argument("job.yaml"),
        argument("job-runtime.example.yaml"),
        argument("profile.yaml"),
        argument("project.yaml"),
    );
    let (exit, text) = run_human(&[
        "job",
        "check",
        &pack,
        &job,
        "--runtime",
        &runtime,
        "--profile",
        &profile,
        "--project",
        &project,
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{text}");
    assert!(
        text.contains("warning[adapter.mapping.script-drift]"),
        "{text}"
    );
    assert!(text.contains("1 warning"), "{text}");
}

#[test]
fn job_check_warns_when_a_generated_pack_script_drifts_from_its_model() {
    std::env::set_var("KOBO_USERNAME", "check-contracts");
    std::env::set_var("KOBO_PASSWORD", "check-contracts");
    let products = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter");
    let root = tempfile::tempdir().unwrap();
    copy_tree(&products.join("examples/kobotoolbox-job"), root.path());
    let pack_directory = root.path().join("pack");
    std::fs::create_dir_all(pack_directory.join("schemas")).unwrap();
    copy_tree(&products.join("packs/kobotoolbox"), &pack_directory);
    std::fs::write(pack_directory.join("schemas/person.schema.json"), SCHEMA).unwrap();
    // A generated script the pack inventories; no route calls it, so only
    // the drift check reads it.
    let model = pack_directory.join("request.mapping.yaml");
    std::fs::write(
        &model,
        model_text(
            "source-request",
            None,
            "scripts/request.rhai",
            "build_request",
        ),
    )
    .unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let pack = pack_directory.join("pack.yaml");
    let text = std::fs::read_to_string(&pack).unwrap();
    std::fs::write(
        &pack,
        text.replace(
            "capabilities:\n",
            &format!(
                "  - path: scripts/request.rhai\n    digest: {}\ncapabilities:\n",
                report["scriptDigest"].as_str().unwrap()
            ),
        ),
    )
    .unwrap();
    let job = root.path().join("job.yaml");
    let (exit, report, _) = run_json(&[
        "job",
        "lock",
        job.to_str().unwrap(),
        "--pack",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["pack"], "updated", "{report}");
    let (exit, report, _) = run_json(&[
        "project",
        "lock",
        root.path().to_str().unwrap(),
        "--pack",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");

    let argument = |name: &str| root.path().join(name).to_str().unwrap().to_owned();
    let check = |extra: &[&str]| {
        let (pack, job, runtime, profile, project) = (
            pack.to_str().unwrap().to_owned(),
            argument("job.yaml"),
            argument("job-runtime.example.yaml"),
            argument("profile.yaml"),
            argument("project.yaml"),
        );
        let mut arguments = vec![
            "job",
            "check",
            pack.as_str(),
            job.as_str(),
            "--runtime",
            runtime.as_str(),
            "--profile",
            profile.as_str(),
            "--project",
            project.as_str(),
        ];
        arguments.extend_from_slice(extra);
        run_json(&arguments)
    };
    let (exit, report, _) = check(&["--deny-warnings"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");

    // Edit the model only: the pack still pins the script bytes, so only the
    // drift warning speaks.
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(
        &model,
        text.replace("constant: person", "constant: individual"),
    )
    .unwrap();
    let (exit, report, _) = check(&[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = drift_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["path"], "/scripts/3", "{report}");
    let (exit, report, _) = check(&["--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
}

// --- unprojected sources in job check --------------------------------------

/// The KoboToolbox job example with a generated destination mapping whose
/// assignments are `assignments` (YAML lines under `assignments:`), the job
/// pinned to the generated script.
fn unprojected_workspace(assignments: &str) -> tempfile::TempDir {
    std::env::set_var("KOBO_USERNAME", "check-contracts");
    std::env::set_var("KOBO_PASSWORD", "check-contracts");
    let products = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter");
    let root = tempfile::tempdir().unwrap();
    copy_tree(&products.join("examples/kobotoolbox-job"), root.path());
    std::fs::create_dir_all(root.path().join("schemas")).unwrap();
    std::fs::write(root.path().join("schemas/person.schema.json"), SCHEMA).unwrap();
    let model = root.path().join("register.mapping.yaml");
    let header = model_text(
        "ingestion",
        Some("proposal"),
        "mappings/register-household.rhai",
        "map_submission",
    );
    let header = header.split("assignments:").next().unwrap().to_owned();
    std::fs::write(&model, format!("{header}assignments:\n{assignments}")).unwrap();
    let (exit, report, _) = run_json(&["mapping", "generate", model.to_str().unwrap(), "--force"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let job = root.path().join("job.yaml");
    let text = std::fs::read_to_string(&job).unwrap();
    let old = "sha256:6b7f1cbbccd57459e15f5ece6282b3ca96946f0525759adcf6acbcc925496da6";
    assert!(text.contains(old));
    std::fs::write(
        &job,
        text.replace(old, report["scriptDigest"].as_str().unwrap()),
    )
    .unwrap();
    root
}

fn job_check_in(root: &tempfile::TempDir, extra: &[&str]) -> (ExitCode, Value, Vec<u8>) {
    let products = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter");
    let pack = products.join("packs/kobotoolbox/pack.yaml");
    let argument = |name: &str| root.path().join(name).to_str().unwrap().to_owned();
    let (pack, job, runtime, profile, project) = (
        pack.to_str().unwrap().to_owned(),
        argument("job.yaml"),
        argument("job-runtime.example.yaml"),
        argument("profile.yaml"),
        argument("project.yaml"),
    );
    let mut arguments = vec![
        "job",
        "check",
        pack.as_str(),
        job.as_str(),
        "--runtime",
        runtime.as_str(),
        "--profile",
        profile.as_str(),
        "--project",
        project.as_str(),
    ];
    arguments.extend_from_slice(extra);
    run_json(&arguments)
}

fn unprojected_warnings(report: &Value) -> Vec<&Value> {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "adapter.job.mapping-unprojected")
        .collect()
}

const PROJECTED_ASSIGNMENTS: &str = "  - target: source.id\n    from: _id\n  \
     - target: source.kind\n    constant: person\n  \
     - target: household.size\n    from: '\"household.household_size\"'\n    convert: integer\n";

#[test]
fn job_check_is_quiet_when_every_source_key_is_projected() {
    let root = unprojected_workspace(PROJECTED_ASSIGNMENTS);
    let (exit, report, _) = job_check_in(&root, &["--deny-warnings"]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert!(unprojected_warnings(&report).is_empty(), "{report}");
}

#[test]
fn job_check_warns_once_for_an_unprojected_top_level_key() {
    let root = unprojected_workspace(
        "  - target: source.id\n    from: _id\n  \
         - target: source.kind\n    from: village\n  \
         - target: household.size\n    from: '\"household.household_size\"'\n    convert: integer\n",
    );
    let (exit, report, _) = job_check_in(&root, &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = unprojected_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    let warning = warnings[0];
    assert_eq!(warning["severity"], "warning", "{report}");
    assert_eq!(warning["path"], "/assignments/1/from", "{report}");
    assert_eq!(warning["target"], "source.kind", "{report}");
    assert!(
        warning["source"]["file"]
            .as_str()
            .unwrap()
            .ends_with("register.mapping.yaml"),
        "{report}"
    );
    let message = warning["message"].as_str().unwrap();
    assert!(message.contains("village"), "{message}");
    assert!(warning["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("projection.fields"));

    let (exit, report, _) = job_check_in(&root, &["--deny-warnings"]);
    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert_eq!(unprojected_warnings(&report).len(), 1, "{report}");
}

#[test]
fn job_check_warns_for_a_keyed_selection_whose_root_is_not_projected() {
    let root = unprojected_workspace(
        "  - target: source.id\n    from: _id\n  \
         - target: source.kind\n    from: 'members[relationship = \"head\"].phone'\n  \
         - target: household.size\n    from: '\"household.household_size\"'\n    convert: integer\n",
    );
    let (exit, report, _) = job_check_in(&root, &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let warnings = unprojected_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["path"], "/assignments/1/from", "{report}");
    assert!(
        warnings[0]["message"].as_str().unwrap().contains("members"),
        "{report}"
    );
    assert!(
        !warnings[0]["message"].as_str().unwrap().contains("head"),
        "{report}"
    );
}

#[test]
fn job_check_addresses_the_assignment_that_reads_the_unprojected_key() {
    let root = unprojected_workspace(
        "  - target: source.id\n    from: _id\n  \
         - target: source.kind\n    constant: person\n  \
         - target: household.size\n    from: size\n    convert: integer\n",
    );
    let (_, report, _) = job_check_in(&root, &[]);
    let warnings = unprojected_warnings(&report);
    assert_eq!(warnings.len(), 1, "{report}");
    assert_eq!(warnings[0]["target"], "household.size", "{report}");
    assert_eq!(warnings[0]["path"], "/assignments/2/from", "{report}");
}

#[test]
fn job_check_says_nothing_new_when_the_script_has_drifted() {
    let root = unprojected_workspace(PROJECTED_ASSIGNMENTS);
    let model = root.path().join("register.mapping.yaml");
    let text = std::fs::read_to_string(&model).unwrap();
    std::fs::write(&model, text.replace("from: _id", "from: village")).unwrap();
    let (exit, report, _) = job_check_in(&root, &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(drift_warnings(&report).len(), 1, "{report}");
    assert!(unprojected_warnings(&report).is_empty(), "{report}");
}

// --- the maintained examples -----------------------------------------------

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples")
        .join(name)
}

/// Preview `model` over `inputs` (file names under `directory`) and return the
/// report with the exact text it printed, for value-leak assertions.
fn preview_examples(directory: &Path, model: &str, inputs: &[&str]) -> (Value, String) {
    let model = directory.join(model);
    let inputs: Vec<String> = inputs
        .iter()
        .map(|name| {
            directory
                .join("preview")
                .join(name)
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let mut arguments = vec!["mapping", "preview", model.to_str().unwrap()];
    for input in &inputs {
        arguments.extend(["--input", input.as_str()]);
    }
    let (exit, report, stderr) = run_json(&arguments);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    let (_, text) = run_human(&arguments);
    let printed = format!("{report}{text}{}", String::from_utf8_lossy(&stderr));
    (report, printed)
}

fn outcomes(report: &Value) -> Vec<(&str, &Value)> {
    report["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| (result["outcome"].as_str().unwrap(), &result["output"]))
        .collect()
}

/// A model, its target schema and the script the repository ships with it,
/// copied so that generation can be re-run without touching the example.
fn assert_generation_reproduces_the_shipped_script(directory: &Path, model: &str, script: &str) {
    let copy = tempfile::tempdir().unwrap();
    copy_tree(directory, copy.path());
    let shipped = std::fs::read(directory.join(script)).unwrap();
    std::fs::remove_file(copy.path().join(script)).unwrap();
    let (exit, report, _) = run_json(&[
        "mapping",
        "generate",
        copy.path().join(model).to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["changed"], true, "{report}");
    assert_eq!(
        std::fs::read(copy.path().join(script)).unwrap(),
        shipped,
        "{script} must be exactly what {model} generates"
    );
}

#[test]
fn dhis2_person_registration_previews_accepted_duplicate_and_invalid_inputs() {
    let directory = example("dhis2-consultation");
    let (report, printed) = preview_examples(
        &directory,
        "person-registration.mapping.yaml",
        &[
            "accepted.json",
            "duplicate-date-of-birth.json",
            "invalid-date-of-birth.json",
        ],
    );
    assert_eq!(report["target"], "consultation");
    let results = outcomes(&report);
    assert_eq!(
        results
            .iter()
            .map(|(outcome, _)| *outcome)
            .collect::<Vec<_>>(),
        ["accepted", "refused", "refused"],
        "{report}"
    );
    assert_eq!(
        results[0].1,
        &json!({
            "registration": {
                "organisationUnit": "SyntheticOu01",
                "lastChangedAt": "2017-05-26T11:46:22.372"
            },
            "person": {"dateOfBirth": "1990-04-17"}
        })
    );
    assert_eq!(report["accepted"], 1);
    assert_eq!(report["refused"], 2);
    for (refused, failure) in report["results"].as_array().unwrap()[1..]
        .iter()
        .zip(["mapping.duplicate", "mapping.conversion"])
    {
        assert!(refused.get("output").is_none(), "{refused}");
        assert_eq!(refused["failure"], failure, "{refused}");
        assert_eq!(refused["field"], "person.dateOfBirth", "{refused}");
    }
    assert!(
        !printed.contains("PRIVATE-CANARY"),
        "a source attribute the model does not select must never be printed"
    );
    // The refusal of a second date of birth carries no source value either.
    assert!(!printed.contains("1991-05-18") && !printed.contains("1990-02-30"));
}

#[test]
fn dhis2_person_registration_script_is_what_its_model_generates() {
    assert_generation_reproduces_the_shipped_script(
        &example("dhis2-consultation"),
        "person-registration.mapping.yaml",
        "scripts/person-registration.rhai",
    );
}

#[test]
fn kobotoolbox_register_household_previews_accepted_and_missing_respondent() {
    let directory = example("kobotoolbox-job");
    let (report, _) = preview_examples(
        &directory,
        "mappings/register-household.mapping.yaml",
        &[
            "accepted-string-id.json",
            "accepted-integer-id.json",
            "missing-respondent.json",
        ],
    );
    assert_eq!(report["target"], "ingestion");
    let results = outcomes(&report);
    assert_eq!(
        results
            .iter()
            .map(|(outcome, _)| *outcome)
            .collect::<Vec<_>>(),
        ["accepted", "accepted", "refused"],
        "{report}"
    );
    assert_eq!(
        results[0].1,
        &json!({
            "startInput": {"input": {
                "sourceSubmissionId": "opaque-submission-001",
                "respondentName": "Fictional Respondent 001",
                "householdSize": 3
            }},
            "submitBody": {}
        })
    );
    assert_eq!(
        results[1].1["startInput"]["input"],
        json!({
            "sourceSubmissionId": "102",
            "respondentName": "Fictional Respondent 102",
            "householdSize": 2
        })
    );
}

#[test]
fn kobotoolbox_register_household_script_is_what_its_model_generates() {
    assert_generation_reproduces_the_shipped_script(
        &example("kobotoolbox-job"),
        "mappings/register-household.mapping.yaml",
        "mappings/register-household.rhai",
    );
}

#[test]
fn source_request_example_checks_and_generates_headlessly() {
    let directory = example("formats/mapping");
    let model = directory.join("tracked-entity-request.mapping.yaml");
    let (exit, report, _) = run_json(&["mapping", "check", model.to_str().unwrap()]);
    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["target"], "source-request");
    assert_generation_reproduces_the_shipped_script(
        &directory,
        "tracked-entity-request.mapping.yaml",
        "scripts/tracked-entity-request.rhai",
    );
}
