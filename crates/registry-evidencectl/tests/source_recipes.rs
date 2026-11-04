#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "the integration test copies reviewed recipe assets"
)]

use registry_adapter_core::AdapterPack;
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence_pack, EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks,
        EvidenceLimits, EvidenceLookup,
    },
    replay::ReplayTranscript,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};

const RECIPES: [(&str, &str); 2] = [
    ("dhis2-tracker", "dhis2-tracker"),
    ("opencrvs-event-search", "opencrvs-event-search"),
];

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

struct ReplayHooks;

impl EvidenceHostHooks for ReplayHooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn exported_recipe_routes_refuse_returned_identity_mismatch_before_facts() {
    assert_extractor_identity_contract(
        "dhis2-tracker",
        "tracked-entity-status",
        json!({"recordReference": "TeiSynthetic01"}),
        json!({
            "endpoint": "tracker",
            "method": "GET",
            "path": "/api/tracker/trackedEntities",
            "query": "fields=trackedEntity%2Cattributes%5Battribute%2Cvalue%5D&orgUnitMode=SELECTED&orgUnits=Org00000001&page=1&pageSize=2&program=Prg00000001&totalPages=true&trackedEntities=TeiSynthetic01",
            "headers": {"accept": "application/json"}
        }),
        dhis2_response(json!("TeiSynthetic01")),
        dhis2_response(json!("TeiSyntheticOther")),
        dhis2_response(json!(1001)),
    )
    .await;
    assert_extractor_identity_contract(
        "opencrvs-event-search",
        "registered-parent",
        json!({"trackingId": "TrackingSynthetic01"}),
        json!({
            "endpoint": "events",
            "method": "POST",
            "path": "/events/search",
            "headers": {"accept": "application/json"},
            "body": {
                "query": {
                    "type": "and",
                    "clauses": [{
                        "eventType": "birth",
                        "status": {"type": "exact", "term": "REGISTERED"},
                        "trackingId": {"type": "exact", "term": "TrackingSynthetic01"}
                    }]
                },
                "limit": 2,
                "offset": 0
            }
        }),
        opencrvs_response(json!("TrackingSynthetic01")),
        opencrvs_response(json!("TrackingSyntheticOther")),
        opencrvs_response(json!(1001)),
    )
    .await;
}

async fn assert_extractor_identity_contract(
    recipe: &str,
    route: &str,
    inputs: Value,
    request: Value,
    matching_response: Value,
    mismatching_response: Value,
    wrong_type_response: Value,
) {
    let pack_root = recipe_root(recipe).join("adapter-packs").join(recipe);
    let pack_path = pack_root.join("pack.yaml");
    let pack_bytes = fs::read(&pack_path).expect("reviewed Adapter pack");
    let pack = Reader::new(pack_path.display().to_string())
        .decode::<AdapterPack>(&pack_bytes, &Expect::one(&ADAPTER_PACK_FORMAT))
        .expect("recipe Adapter pack follows the current typed grammar")
        .value;
    let artifacts = PackArtifactBytes::new(pack.pinned_files().into_iter().map(|reference| {
        let relative = reference.path.as_str().to_owned();
        let bytes = fs::read(pack_root.join(&relative)).expect("pinned recipe pack artifact");
        (relative, bytes)
    }));

    for (case, response) in [
        ("matching value", matching_response),
        ("different value", mismatching_response),
        ("different scalar type", wrong_type_response),
    ] {
        let checked = compile_evidence_pack(&pack, route, &artifacts, EvidenceLimits::default())
            .expect("the exact exported pack closure compiles without I/O");
        let endpoint = request["endpoint"].clone();
        let mut intercepts = vec![json!({"type":"endpoint","endpoint":endpoint})];
        let mut exchanges = Vec::new();
        if recipe == "opencrvs-event-search" {
            intercepts.push(json!({"type":"token-endpoint","endpoint":"events"}));
            exchanges.push(json!({
                "request": {
                    "endpoint": "events",
                    "tokenRequest": true,
                    "method": "POST",
                    "path": "/token"
                },
                "response": {
                    "status": 200,
                    "body": {
                        "access_token": "synthetic-replay-token",
                        "token_type": "Bearer",
                        "expires_in": 300
                    }
                }
            }));
        }
        exchanges.push(json!({
            "request": request.clone(),
            "response": {"status": 200, "body": response}
        }));
        let transcript = Arc::new(ReplayTranscript::from_exchanges(
            serde_json::from_value(Value::Array(intercepts)).expect("endpoint intercepts"),
            serde_json::from_value(Value::Array(exchanges)).expect("sealed recipe exchanges"),
        ));
        let program = checked
            .bind_replay(Arc::clone(&transcript))
            .expect("the checked pack binds to replay only");
        let acquisition = program
            .begin_acquisition(Arc::new(ReplayHooks))
            .await
            .expect("the replay acquisition begins");
        let outcome = program.execute(&acquisition, inputs.clone()).await;
        if case == "matching value" {
            assert!(
                matches!(outcome, Ok(EvidenceLookup::Matched { .. })),
                "{recipe} matching identity must release reviewed private facts, got {outcome:?}"
            );
            transcript
                .finish()
                .expect("the matching route consumes its sealed exchange");
        } else {
            assert!(
                outcome.is_err(),
                "{recipe} {case} must be refused before facts, got {outcome:?}"
            );
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
            .join("adapter-packs")
            .join(source_id)
            .join("scripts/source-recipe.rhai");
        let upstream = fs::read_to_string(&function).expect("imported pack route script");
        let customized = format!("{upstream}// institution-owned review note\n");
        fs::write(&function, &customized).expect("customize imported pack script");
        let pack_relative = format!("adapter-packs/{source_id}/pack.yaml");
        let script_relative = format!("adapter-packs/{source_id}/scripts/source-recipe.rhai");
        update_pack_pin(
            &project.join(&pack_relative),
            "scripts/source-recipe.rhai",
            customized.as_bytes(),
        );

        let next = workspace.path().join("next-export");
        copy_export(&export, &next);
        let adapter = next
            .join("adapter-packs")
            .join(source_id)
            .join("scripts/source-recipe.rhai");
        let revised = format!(
            "{}// reviewed upstream revision\n",
            fs::read_to_string(&adapter).expect("recipe pack script")
        );
        fs::write(&adapter, &revised).expect("revise next export");
        update_manifest_digest(&next, &script_relative, revised.as_bytes());
        let revised_pack = update_pack_pin(
            &next.join(&pack_relative),
            "scripts/source-recipe.rhai",
            revised.as_bytes(),
        );
        update_manifest_digest(&next, &pack_relative, &revised_pack);

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
        let conflict_path = script_relative;
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
                "artifacts": {
                    conflict_path.clone(): {"type": "keep"},
                    pack_relative: {"type": "keep"}
                }
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
            fs::read_to_string(&function).expect("detached pack script"),
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
                .join("adapter-packs")
                .join(source_id)
                .join("scripts/source-recipe.rhai"),
            "fn lookup(exchange) { exchange.body }\n",
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
    for directory in ["adapter-packs", "selectors", "sources"] {
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

fn update_pack_pin(pack_path: &Path, artifact_path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut pack: Value =
        serde_norway::from_slice(&fs::read(pack_path).expect("read Adapter pack"))
            .expect("parse Adapter pack");
    let artifact = pack["scripts"]
        .as_array_mut()
        .expect("pack script inventory")
        .iter_mut()
        .find(|artifact| artifact["path"] == artifact_path)
        .expect("script pin in pack");
    artifact["digest"] = Value::String(registry_platform_config::sha256_uri(bytes));
    let rendered = serde_norway::to_string(&pack)
        .expect("serialize Adapter pack")
        .into_bytes();
    fs::write(pack_path, &rendered).expect("write Adapter pack");
    rendered
}
