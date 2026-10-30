#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "the integration test copies reviewed recipe assets"
)]

use registry_evidence::{
    model::LookupResult,
    rhai_runtime::{RhaiRuntime, RhaiRuntimeError},
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const RECIPES: [(&str, &str); 2] = [
    ("dhis2-tracker", "dhis2-tracker"),
    ("opencrvs-event-search", "opencrvs-event-search"),
];

#[test]
fn exported_recipe_extractors_refuse_returned_identity_mismatch_before_facts() {
    assert_extractor_identity_contract(
        "dhis2-tracker",
        json!({
            "program": "Prg00000001",
            "organisationUnit": "Org00000001",
            "projection": "trackedEntity,attributes[attribute,value]",
            "pageSize": "2",
            "page": "1",
            "totalPages": "true",
            "statusAttribute": "Sta00000001"
        }),
        json!({
            "subject": {
                "profile": "dhis2-tracked-entity-id-v1",
                "values": {"record_reference": "TeiSynthetic01"}
            }
        }),
        dhis2_response(json!("TeiSynthetic01")),
        dhis2_response(json!("TeiSyntheticOther")),
        dhis2_response(json!(1001)),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["record_reference", "status_code"],
            "properties": {
                "record_reference": {"type": "string"},
                "status_code": {"type": "string"}
            }
        }),
    );
    assert_extractor_identity_contract(
        "opencrvs-event-search",
        json!({
            "eventType": "birth",
            "registeredStatus": "REGISTERED",
            "resultLimit": 2,
            "resultOffset": 0,
            "parentReferenceFields": ["mother.personReference", "father.personReference"],
            "minimumParentReferences": 1,
            "maximumParentReferences": 2,
            "parentReferenceNamespace": "urn:gov:example:opencrvs:person",
            "relationshipSetContract": "urn:gov:example:opencrvs:registered-parent-set:v1",
            "relationshipSetComplete": true,
            "absentConfiguredFieldMeansNoRegisteredParent": true
        }),
        json!({
            "child": {
                "profile": "opencrvs-tracking-id-v1",
                "values": {"tracking_id": "TrackingSynthetic01"}
            }
        }),
        opencrvs_response(json!("TrackingSynthetic01")),
        opencrvs_response(json!("TrackingSyntheticOther")),
        opencrvs_response(json!(1001)),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": [
                "record_tracking_id",
                "parent_references",
                "reference_namespace",
                "relationship_set_contract",
                "relationship_set_complete"
            ],
            "properties": {
                "record_tracking_id": {"type": "string"},
                "parent_references": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "uniqueItems": true,
                    "items": {"type": "string"}
                },
                "reference_namespace": {"const": "urn:gov:example:opencrvs:person"},
                "relationship_set_contract": {"const": "urn:gov:example:opencrvs:registered-parent-set:v1"},
                "relationship_set_complete": {"const": true}
            }
        }),
    );
}

fn assert_extractor_identity_contract(
    recipe: &str,
    parameters: Value,
    selectors: Value,
    matching_response: Value,
    mismatching_response: Value,
    wrong_type_response: Value,
    fact_schema: Value,
) {
    let source_id = recipe;
    let script_path = recipe_root(recipe)
        .join("adapters")
        .join(format!("{source_id}-extract.rhai"));
    let script_source = fs::read_to_string(&script_path).expect("reviewed extraction Function");
    let runtime = RhaiRuntime::new();
    let script = runtime
        .compile_extraction(&script_source)
        .expect("recipe extraction Function compiles in the real runtime");
    let schema = jsonschema::JSONSchema::compile(&fact_schema).expect("recipe fact schema");
    let prior_facts = BTreeMap::new();

    let matched = runtime
        .extract_with_selectors(
            &script,
            &matching_response,
            &selectors,
            &parameters,
            &prior_facts,
            &schema,
        )
        .expect("matching returned identity extracts facts");
    assert!(matches!(matched, LookupResult::Match(_)));

    for (case, response) in [
        ("different value", mismatching_response),
        ("different scalar type", wrong_type_response),
    ] {
        match runtime.extract_with_selectors(
            &script,
            &response,
            &selectors,
            &parameters,
            &prior_facts,
            &schema,
        ) {
            Err(RhaiRuntimeError::SourceProtocol) => {}
            Err(other) => panic!(
                "{} {case} must be a source protocol error, got {other:?}",
                script_path.display()
            ),
            Ok(_) => panic!(
                "{} {case} must be refused before facts",
                script_path.display()
            ),
        }
    }
}

fn dhis2_response(record_reference: Value) -> Value {
    json!({
        "pager": {"page": 1, "pageSize": 2, "total": 1, "pageCount": 1},
        "trackedEntities": [{
            "trackedEntity": record_reference,
            "attributes": [{"attribute": "Sta00000001", "value": "ACTIVE"}]
        }]
    })
}

fn opencrvs_response(tracking_id: Value) -> Value {
    json!({
        "total": 1,
        "results": [{
            "type": "birth",
            "status": "REGISTERED",
            "trackingId": tracking_id,
            "declaration": {"mother.personReference": "PersonSyntheticA"}
        }]
    })
}

#[test]
fn curated_source_recipes_cover_the_source_import_lifecycle() {
    for (recipe, source_id) in RECIPES {
        let workspace = tempfile::tempdir().expect("temporary recipe workspace");
        let export = recipe_root(recipe);
        let project = workspace.path().join("project");
        copy_tree(&export.join("fixture-validation"), &project);

        assert_success(&evidencectl([
            OsStr::new("source"),
            OsStr::new("import"),
            export.as_os_str(),
            OsStr::new("--project"),
            project.as_os_str(),
        ]));

        let function = project
            .join("functions")
            .join(format!("{source_id}-extract.rhai"));
        let upstream = fs::read_to_string(&function).expect("imported extraction Function");
        let customized = format!("{upstream}// institution-owned review note\n");
        fs::write(&function, &customized).expect("customize imported Function");

        let next = workspace.path().join("next-export");
        copy_export(&export, &next);
        let adapter = next
            .join("adapters")
            .join(format!("{source_id}-extract.rhai"));
        let revised = format!(
            "{}// reviewed upstream revision\n",
            fs::read_to_string(&adapter).expect("recipe extraction Function")
        );
        fs::write(&adapter, &revised).expect("revise next export");
        update_manifest_digest(
            &next,
            &format!("adapters/{source_id}-extract.rhai"),
            revised.as_bytes(),
        );

        let diff = evidencectl([
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("source"),
            OsStr::new("diff"),
            next.as_os_str(),
            OsStr::new("--project"),
            project.as_os_str(),
        ]);
        assert_success(&diff);
        let report: Value = serde_json::from_slice(&diff.stdout).expect("source diff JSON report");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["outcome"], "conflict");
        assert_eq!(report["validation"]["status"], "conflict");
        let conflict_path = format!("functions/{source_id}-extract.rhai");
        assert!(report["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .any(|path| path.as_str() == Some(conflict_path.as_str())));
        assert_eq!(
            fs::read_to_string(&function).expect("customization after diff"),
            customized
        );

        let resolutions = workspace.path().join("source-resolutions.json");
        fs::write(
            &resolutions,
            serde_json::to_vec_pretty(&serde_json::json!({
                "apiVersion": "id.registrystack.org/formats/evidence/source-resolution/v1alpha1",
                "kind": "EvidenceSourceResolution",
                "artifacts": {format!("functions/{source_id}-extract.rhai"): {"type": "keep"}}
            }))
            .expect("serialize resolution"),
        )
        .expect("write resolution");
        assert_success(&evidencectl([
            OsStr::new("source"),
            OsStr::new("update"),
            next.as_os_str(),
            OsStr::new("--project"),
            project.as_os_str(),
            OsStr::new("--resolutions"),
            resolutions.as_os_str(),
        ]));
        assert_eq!(
            fs::read_to_string(&function).expect("retained customization"),
            customized
        );

        assert_success(&evidencectl([
            OsStr::new("source"),
            OsStr::new("detach"),
            OsStr::new(source_id),
            project.as_os_str(),
        ]));
        assert_eq!(
            fs::read_to_string(&function).expect("detached Function"),
            customized
        );
        let refused = evidencectl([
            OsStr::new("source"),
            OsStr::new("update"),
            export.as_os_str(),
            OsStr::new("--project"),
            project.as_os_str(),
        ]);
        assert!(!refused.status.success());
        assert!(
            printed(&refused).contains("detached"),
            "{}",
            printed(&refused)
        );
    }
}

#[test]
fn curated_source_recipes_refuse_checksum_tampering_without_project_changes() {
    for (recipe, source_id) in RECIPES {
        let workspace = tempfile::tempdir().expect("temporary recipe workspace");
        let export = workspace.path().join("tampered-export");
        copy_export(&recipe_root(recipe), &export);
        let project = workspace.path().join("project");
        copy_tree(&recipe_root(recipe).join("fixture-validation"), &project);
        let project_before =
            fs::read(project.join("evidence.yaml")).expect("project before import");
        fs::write(
            export
                .join("adapters")
                .join(format!("{source_id}-extract.rhai")),
            "fn extract(response, context) { response }\n",
        )
        .expect("tamper asset");

        let output = evidencectl([
            OsStr::new("source"),
            OsStr::new("import"),
            export.as_os_str(),
            OsStr::new("--project"),
            project.as_os_str(),
        ]);
        assert!(!output.status.success());
        assert!(
            printed(&output).contains("checksum"),
            "{}",
            printed(&output)
        );
        assert_eq!(
            fs::read(project.join("evidence.yaml")).expect("project after refusal"),
            project_before
        );
        assert!(!project.join(".evidence/source-imports/state.json").exists());
    }
}

#[test]
fn source_recipe_harness_refuses_missing_assembly_inputs() {
    for failure in ["missing-marker", "missing-fragment"] {
        let workspace = tempfile::tempdir().expect("temporary recipe workspace");
        let catalog = workspace.path().join("source-recipes");
        copy_tree(&source_recipe_catalog(), &catalog);
        let validation = catalog.join("dhis2-tracker/fixture-validation");
        if failure == "missing-marker" {
            let seed = validation.join("evidence.yaml");
            let authored = fs::read_to_string(&seed).expect("validation seed");
            let without_marker = authored.replace("# SOURCE_RECIPE_ASSERTION_DEFINITIONS\n", "");
            assert_ne!(without_marker, authored);
            fs::write(seed, without_marker).expect("remove copied insertion marker");
        } else {
            fs::remove_file(validation.join("assertion-definitions.yaml"))
                .expect("remove copied assertion fragment");
        }

        let output = Command::new("bash")
            .arg(catalog.join("run-fixtures.sh"))
            .env("EVIDENCECTL_BIN", env!("CARGO_BIN_EXE_evidencectl"))
            .env_remove("EVIDENCE_BIN")
            .output()
            .expect("run copied source recipe fixture harness");
        assert!(!output.status.success(), "{failure}: {}", printed(&output));
        assert!(
            !printed(&output).contains("Evidence source recipe fixtures passed"),
            "{failure}: {}",
            printed(&output)
        );
    }
}

#[test]
#[ignore = "exact gate: needs the real Evidence binary in EVIDENCE_BIN"]
fn curated_source_recipes_import_check_and_run_the_existing_evaluator() {
    let evidence = std::env::var_os("EVIDENCE_BIN")
        .expect("set EVIDENCE_BIN to the Evidence binary built from this source");
    let harness = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/source-recipes/run-fixtures.sh");
    let output = Command::new("bash")
        .arg(harness)
        .env("EVIDENCECTL_BIN", env!("CARGO_BIN_EXE_evidencectl"))
        .env("EVIDENCE_BIN", evidence)
        .output()
        .expect("run the shipped source recipe fixture harness");
    assert_success(&output);
    let report = printed(&output);
    assert!(
        report.contains("fixtures/active-status.yaml (6 cases)"),
        "{report}"
    );
    assert!(
        report.contains("fixtures/registered-parent.yaml (6 cases)"),
        "{report}"
    );
}

fn source_recipe_catalog() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/source-recipes")
}

fn recipe_root(recipe: &str) -> PathBuf {
    source_recipe_catalog().join(recipe)
}

fn evidencectl<const N: usize>(arguments: [&OsStr; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("run evidencectl")
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", printed(output));
}

fn printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn copy_export(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create export destination");
    for directory in ["adapters", "schemas", "selectors", "sources"] {
        copy_tree(&source.join(directory), &destination.join(directory));
    }
    fs::copy(
        source.join("source-export.json"),
        destination.join("source-export.json"),
    )
    .expect("copy source export manifest");
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination directory");
    for entry in fs::read_dir(source).expect("read source directory") {
        let entry = entry.expect("source directory entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let kind = entry.file_type().expect("source entry type");
        assert!(
            !kind.is_symlink(),
            "recipe assets must not be symbolic links"
        );
        if kind.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            assert!(kind.is_file(), "recipe assets must be plain files");
            fs::copy(&source_path, &destination_path).expect("copy recipe asset");
        }
    }
}

fn update_manifest_digest(export: &Path, artifact_path: &str, bytes: &[u8]) {
    let manifest_path = export.join("source-export.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifact inventory")
        .iter_mut()
        .find(|artifact| artifact["path"] == artifact_path)
        .expect("revised artifact in manifest");
    artifact["digest"] = Value::String(format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
}
