// SPDX-License-Identifier: Apache-2.0

use registry_language_server::execute_workspace_analysis;
use serde_json::{json, Value};
use std::process::{Command, Stdio};

const API_VERSION: &str = "id.registrystack.org/formats/platform/workspace-analysis/v1alpha1";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn file(path: &str, bytes_base64: &str, sha256: &str) -> Value {
    json!({
        "path": path,
        "state": "document",
        "sha256": sha256,
        "bytesBase64": bytes_base64,
    })
}

fn identity(scope: &str, name: &str) -> Value {
    json!({ "kind": "object", "scope": scope, "name": name })
}

fn definition(scope: &str, name: &str, file: &str) -> Value {
    json!({ "scope": scope, "name": name, "file": file, "pointer": "" })
}

fn mention(
    source_scope: &str,
    source_name: &str,
    target_scope: &str,
    target_name: &str,
    kind: &str,
) -> Value {
    json!({
        "source": { "scope": source_scope, "name": source_name },
        "target": { "scope": target_scope, "name": target_name },
        "kind": kind,
        "file": "actions/a.yaml",
        "pointer": "/target",
    })
}

fn request(operation: &str) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "operation": operation,
        "workspaceBinding": "workspace:test",
        "revision": "revision-1",
        "files": [file("actions/a.yaml", "YWJj", ABC_SHA256)],
        "facts": {
            "definitions": [],
            "mentions": [],
            "mappings": [],
            "coverageGaps": [{
                "code": "reference-family-unavailable",
                "message": "Only normalized test facts were supplied."
            }],
            "checkGroups": ["workspace-v1"]
        }
    })
}

#[test]
fn analysis_verifies_bytes_and_builds_a_deterministic_snapshot() {
    let output = execute_workspace_analysis(request("analyze")).expect("analysis succeeds");
    assert_eq!(output["engine"]["name"], "registry-language-server");
    assert_eq!(output["analysis"]["apiVersion"], API_VERSION);
    assert_eq!(
        output["analysis"]["snapshot"]["contentHash"],
        "045725e0e9cf7b2ce34091ce072c8101014524c3e591ff6ccab1f3c9b3a1b8e1"
    );
    assert_eq!(output["analysis"]["files"][0]["contentHash"], ABC_SHA256);

    let mut wrong_digest = request("analyze");
    wrong_digest["files"][0]["sha256"] = Value::String("0".repeat(64));
    let error = execute_workspace_analysis(wrong_digest).expect_err("digest mismatch is refused");
    assert_eq!(error.code(), "content-hash-mismatch");

    let mut unsafe_path = request("analyze");
    unsafe_path["files"][0]["path"] = Value::String("../secret".to_owned());
    let error = execute_workspace_analysis(unsafe_path).expect_err("unsafe path is refused");
    assert_eq!(error.code(), "invalid-path");
}

#[test]
fn subprocess_reads_and_writes_the_versioned_json_contract() {
    let binary = env!("CARGO_BIN_EXE_registry-language-server");
    let mut child = Command::new(binary)
        .arg("--workspace-analysis")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("workspace analysis subprocess starts");
    serde_json::to_writer(
        child.stdin.as_mut().expect("subprocess stdin"),
        &request("analyze"),
    )
    .expect("request writes");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("subprocess exits");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON response");
    assert_eq!(response["apiVersion"], API_VERSION);
    assert_eq!(response["analysis"]["snapshot"]["revision"], "revision-1");
}

#[test]
fn exact_binary_native_bytes_remain_bound_with_explicit_opaque_coverage() {
    let mut input = request("analyze");
    input["files"] = json!([{
        "path": "native/logo.bin",
        "state": "native",
        "sha256": "ea5dbf9596d187e9500f23e9a680109475341cf4e81f7e043f7d97152c10772f",
        "bytesBase64": "/wA="
    }]);
    input["facts"]["nativeParts"] = json!(["native/logo.bin"]);

    let output = execute_workspace_analysis(input).expect("binary native content stays hash-bound");
    assert_eq!(
        output["analysis"]["files"][0]["contentHash"],
        "ea5dbf9596d187e9500f23e9a680109475341cf4e81f7e043f7d97152c10772f"
    );
    assert!(output["analysis"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |gap| gap["code"] == "native-provider-unavailable" && gap["file"] == "native/logo.bin"
        ));
}

#[test]
fn analysis_resolves_scoped_identities_and_reports_unresolved_targets() {
    let mut input = request("analyze");
    input["facts"]["definitions"] = json!([
        definition("actions", "apply", "actions/a.yaml"),
        definition("records", "licence", "actions/a.yaml"),
        definition("services", "apply", "actions/a.yaml")
    ]);
    input["facts"]["mentions"] = json!([
        mention("actions", "apply", "records", "licence", "action-record"),
        mention("services", "apply", "records", "missing", "service-record")
    ]);

    let output = execute_workspace_analysis(input).expect("analysis succeeds");
    let references = output["analysis"]["references"]
        .as_array()
        .expect("references array");
    assert_eq!(references.len(), 2);
    assert_eq!(references[0]["resolution"], "resolved");
    assert_eq!(references[0]["target"], identity("records", "licence"));
    assert_eq!(references[1]["resolution"], "unresolved");
    assert!(output["analysis"]["coverage"]["gaps"]
        .as_array()
        .expect("coverage gaps")
        .iter()
        .any(|gap| gap["code"] == "unresolved-reference"));
}

#[test]
fn absent_authored_file_targets_are_safe_unresolved_identities() {
    let mut input = request("analyze");
    input["facts"]["definitions"] = json!([definition("actions", "apply", "actions/a.yaml")]);
    input["facts"]["mentions"] = json!([{
        "source": identity("actions", "apply"),
        "target": { "kind": "authored-file", "path": "logic/missing.rhai" },
        "kind": "action-logic-source",
        "file": "actions/a.yaml",
        "pointer": "/changes/0/file"
    }]);

    let output = execute_workspace_analysis(input).expect("missing target remains analyzable");
    assert_eq!(
        output["analysis"]["references"][0]["resolution"],
        "unresolved"
    );
    assert!(output["analysis"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["code"] == "unresolved-reference" && gap["file"] == "actions/a.yaml"));
}

#[test]
fn declared_mapping_retains_a_missing_repairable_authored_source() {
    let mut input = request("analyze");
    input["facts"]["definitions"] = json!([definition("actions", "apply", "actions/a.yaml")]);
    input["facts"]["mappings"] = json!([{
        "owner": identity("actions", "apply"),
        "authored": { "kind": "authored-file", "path": "logic/missing.rhai" },
        "generated": { "kind": "generated-file", "path": "registry/plans/missing.rhai" },
        "product": "breg",
        "file": "actions/a.yaml",
        "pointer": "/nativeParts/0/mapping/targetFile"
    }]);

    let output = execute_workspace_analysis(input).expect("missing mapped source is repairable");
    assert_eq!(
        output["analysis"]["declaredMappings"][0]["authored"],
        json!({ "kind": "authored-file", "path": "logic/missing.rhai" })
    );
    assert!(output["analysis"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["code"] == "source-unreadable" && gap["file"] == "logic/missing.rhai"));
}

#[test]
fn reference_query_returns_incoming_and_outgoing_edges() {
    let mut input = request("references");
    input["facts"]["definitions"] = json!([
        definition("actions", "apply", "actions/a.yaml"),
        definition("records", "licence", "actions/a.yaml")
    ]);
    input["facts"]["mentions"] = json!([mention(
        "actions",
        "apply",
        "records",
        "licence",
        "action-record"
    )]);
    input["target"] = identity("records", "licence");

    let output = execute_workspace_analysis(input).expect("query succeeds");
    assert_eq!(output["references"]["targetExists"], true);
    assert_eq!(
        output["references"]["incoming"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        output["references"]["outgoing"].as_array().unwrap().len(),
        0
    );
}

#[test]
fn impact_keeps_removed_edges_and_transitive_unchanged_consumers() {
    let before_facts = json!({
        "definitions": [
            definition("records", "licence", "actions/a.yaml"),
            definition("actions", "apply", "actions/a.yaml"),
            definition("services", "licensing", "actions/a.yaml")
        ],
        "mentions": [
            mention("actions", "apply", "records", "licence", "action-record"),
            mention("services", "licensing", "actions", "apply", "service-action")
        ],
        "mappings": [],
        "coverageGaps": [{
            "code": "reference-family-unavailable",
            "message": "Only normalized test facts were supplied."
        }],
        "checkGroups": ["workspace-v1"]
    });
    let mut input = request("impact");
    input["facts"]["definitions"] = before_facts["definitions"].clone();
    input["facts"]["mentions"] = json!([mention(
        "services",
        "licensing",
        "actions",
        "apply",
        "service-action"
    )]);
    input["before"] = json!({
        "workspaceBinding": "workspace:test",
        "revision": "revision-0",
        "files": [file("actions/a.yaml", "YWJj", ABC_SHA256)],
        "facts": before_facts
    });
    input["targets"] = json!([identity("records", "licence")]);

    let output = execute_workspace_analysis(input).expect("impact succeeds");
    let impact = &output["impact"];
    assert_eq!(
        impact["changes"]["removedReferences"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let affected = impact["affected"].as_array().expect("affected objects");
    assert!(affected
        .iter()
        .any(|item| item["identity"] == identity("actions", "apply")));
    assert!(affected.iter().any(|item| {
        item["identity"] == identity("services", "licensing") && item["reason"] == "dependent"
    }));
    assert!(impact["paths"].as_array().unwrap().iter().any(|path| {
        path["from"] == identity("records", "licence")
            && path["to"] == identity("services", "licensing")
            && path["references"].as_array().unwrap().len() == 2
    }));
}

#[test]
fn generation_facts_require_the_exact_snapshot() {
    let mut input = request("analyze");
    input["facts"]["definitions"] = json!([definition("actions", "apply", "actions/a.yaml")]);
    input["facts"]["generation"] = json!({
        "snapshot": {
            "workspaceBinding": "workspace:test",
            "revision": "stale",
            "contentHash": "045725e0e9cf7b2ce34091ce072c8101014524c3e591ff6ccab1f3c9b3a1b8e1"
        },
        "generator": { "id": "registry-test", "version": "1" },
        "files": [{
            "path": "generated/apply.json",
            "source": { "type": "product", "product": "breg", "items": ["actions:apply"] }
        }]
    });

    let output =
        execute_workspace_analysis(input).expect("analysis succeeds with partial coverage");
    assert!(output["analysis"]["provenance"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(output["analysis"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["code"] == "generation-revision-mismatch"));
}

#[test]
fn mapped_breg_native_yaml_uses_the_rust_product_reference_provider() {
    let mut input = request("analyze");
    input["files"] = json!([{
        "path": "native/module.yaml",
        "state": "native",
        "sha256": "a665b1d0a242207e71422780c31766027b61b283d5806a601c380597b8ba5d39",
        "bytesBase64": "a2luZDogQlJlZ01vZHVsZQppZDogZXh0cmEKZXh0ZW5kUmVjb3JkVHlwZXM6CiAgLSByZWNvcmRUeXBlOiBwZXJzb24K"
    }]);
    input["facts"]["definitions"] = json!([definition("records", "person", "native/module.yaml")]);
    input["facts"]["nativeParts"] = json!(["native/module.yaml"]);
    input["facts"]["mappings"] = json!([{
        "owner": identity("records", "person"),
        "authored": { "kind": "authored-file", "path": "native/module.yaml" },
        "generated": { "kind": "generated-file", "path": "registry/modules/extra/module.yaml" },
        "product": "breg",
        "file": "native/module.yaml",
        "pointer": ""
    }]);

    let output = execute_workspace_analysis(input).expect("native BReg analysis succeeds");
    assert!(output["analysis"]["references"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reference| {
            reference["kind"] == "native-breg-record-type"
                && reference["source"]
                    == json!({ "kind": "authored-file", "path": "native/module.yaml" })
                && reference["target"] == identity("records", "person")
                && reference["resolution"] == "resolved"
        }));
    assert!(!output["analysis"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["code"] == "native-provider-unavailable"
            && gap["file"] == "native/module.yaml"));
}
