#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn export(output: &Path, fields: &str) -> Output {
    export_with_flags(output, fields, &[])
}

fn export_with_flags(output: &Path, fields: &str, flags: &[&str]) -> Output {
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/evidence/registry")
        .canonicalize()
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
            "record",
            "--selector",
            "by-code",
            "--selector",
            "by-registration-number",
            "--fields",
            fields,
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
            "--output",
        ])
        .arg(output)
        .args(flags)
        .output()
        .unwrap()
}

#[test]
fn explicit_pack_authentication_is_emitted() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("oauth-export");
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/evidence/registry")
        .canonicalize()
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
            "record",
            "--selector",
            "by-code",
            "--fields",
            "status",
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
            "--authentication",
            "oauth2-private-key-jwt",
            "--output",
        ])
        .arg(&destination)
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let pack: Value = serde_norway::from_slice(
        &fs::read(destination.join("adapter-packs/registry-status/pack.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        pack["endpoints"][0]["authentication"],
        serde_json::json!({"type":"oauth2-private-key-jwt"})
    );
}

#[test]
fn native_export_is_create_only_and_reports_selected_contract() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("export");
    let result = export(&destination, "status");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["explanation"]["connection"], "registry");
    assert_eq!(
        report["explanation"]["selectorProfiles"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    let manifest = fs::read(destination.join("source-export.json")).unwrap();
    let source: Value = serde_norway::from_slice(
        &fs::read(destination.join("sources/registry-status.yaml")).unwrap(),
    )
    .unwrap();
    let pack: Value = serde_norway::from_slice(
        &fs::read(destination.join("adapter-packs/registry-status/pack.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(source["pack"]["id"], "registry-status");
    assert_eq!(source["route"], "lookup");
    assert_eq!(source["inputs"].as_object().unwrap().len(), 2);
    assert_eq!(
        pack["endpoints"][0]["authentication"]["type"],
        "static-authorization"
    );
    assert!(!String::from_utf8_lossy(&manifest).contains("SYNTHETIC-PRIVATE-LABEL"));
    fs::write(destination.join("author-note"), "preserve this work").unwrap();
    assert!(!export(&destination, "status").status.success());
    assert_eq!(
        fs::read(destination.join("source-export.json")).unwrap(),
        manifest
    );
    assert_eq!(
        fs::read_to_string(destination.join("author-note")).unwrap(),
        "preserve this work"
    );
}

#[test]
fn native_export_refuses_unreadable_facts_without_publishing_partial_files() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("refused");
    let result = export(&destination, "label");
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.evidence-source.refused"
    );
    assert!(!destination.exists());
}

#[test]
fn an_explicit_lookup_project_exports_an_evidence_source_without_edits() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = root.join("registry");
    fs::create_dir(&project).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/registry/registry.yaml"),
        project.join("registry.yaml"),
    )
    .unwrap();

    let destination = root.join("export");
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(&project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
            "record",
            "--selector",
            "by-code",
            "--fields",
            "status",
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
            "--output",
        ])
        .arg(&destination)
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        report["explanation"]["selectorProfiles"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(destination.join("sources/registry-status.yaml").exists());
}

/// The `breg/evidence-source-export` format's example is the manifest this
/// export writes, committed as written. Rewrite it from the repository root:
///
/// ```text
/// bregctl generate evidence-source products/breg/evidence/registry \
///   --access-profile evidence-source --record-type record \
///   --selector by-code --selector by-registration-number --fields status \
///   --source-id registry-status --connection registry --output "$export"
/// cp "$export/source-export.json" products/breg/examples/formats/
/// ```
#[test]
fn committed_example_is_the_manifest_bregctl_writes() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("export");
    let result = export(&destination, "status");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/formats/source-export.json");
    assert!(
        fs::read(destination.join("source-export.json")).unwrap() == fs::read(&example).unwrap(),
        "{example:?} is not the manifest `bregctl generate evidence-source` writes now; \
         rewrite it with the command in this test's comment"
    );
}

fn export_with(output: &Path, extra: &[&str]) -> Output {
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/evidence/registry")
        .canonicalize()
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
            "record",
            "--selector",
            "by-code",
            "--fields",
            "status",
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
        ])
        .args(extra)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn required_values_and_optional_facts_reach_the_generated_pack() {
    let temp = tempfile::tempdir().unwrap();
    let guarded = temp.path().canonicalize().unwrap().join("guarded");
    let result = export_with(
        &guarded,
        &[
            "--require-value",
            "status=active",
            "--require-value",
            "status=retired",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let script =
        fs::read_to_string(guarded.join("adapter-packs/registry-status/scripts/lookup.rhai"))
            .unwrap();
    assert!(script.contains(
        "if ![\"active\", \"retired\"].contains(record[\"status\"]) { return #{lookup: \"no-match\"}; }"
    ));

    let optional = temp.path().canonicalize().unwrap().join("optional");
    let result = export_with(&optional, &["--optional-fields", "status"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let facts: Value = serde_json::from_slice(
        &fs::read(optional.join("adapter-packs/registry-status/schemas/facts.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(facts["required"], serde_json::json!([]));
}

#[test]
fn invalid_fact_rule_flags_are_refused_without_publishing_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for (name, extra, code) in [
        (
            "no-equals",
            vec!["--require-value", "status"],
            "evidence-source.arguments",
        ),
        (
            "wrong-value",
            vec!["--require-value", "status=not-a-status"],
            "breg.evidence-source.refused",
        ),
        (
            "both",
            vec![
                "--require-value",
                "status=active",
                "--optional-fields",
                "status",
            ],
            "breg.evidence-source.refused",
        ),
    ] {
        let destination = root.join(name);
        let result = export_with(&destination, &extra);
        assert!(!result.status.success(), "{name}");
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["diagnostics"][0]["code"], code, "{name}");
        assert!(!destination.exists(), "{name}");
    }
}

#[test]
fn evidence_source_flags_apply_only_to_evidence_source() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/evidence/registry")
        .canonicalize()
        .unwrap();
    // The argument check runs before either facts target reads this file.
    let runtime = root.join("runtime.yaml");
    for (artifact, code) in [
        ("odrl", "odrl.arguments"),
        ("identity-facts", "identity-facts.arguments"),
        ("external-source-facts", "external-source-facts.arguments"),
    ] {
        for flags in [
            &["--require-value", "status=active"][..],
            &["--optional-fields", "status"],
            &["--public-check"],
        ] {
            let output = root.join("output");
            let mut command = Command::new(env!("CARGO_BIN_EXE_bregctl"));
            command.env_remove("REGISTRY_STACK_POSTURE");
            command
                .args(["--format", "json", "generate", artifact])
                .arg(&project)
                .args(flags)
                .arg("--output")
                .arg(&output);
            if artifact != "odrl" {
                command.arg("--runtime-config").arg(&runtime);
            }
            let result = command.output().unwrap();
            assert!(!result.status.success(), "{artifact} {flags:?}");
            let report: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(
                report["diagnostics"][0]["code"], code,
                "{artifact} {flags:?}"
            );
            let message = report["diagnostics"][0]["message"].as_str().unwrap();
            assert!(message.contains("accepts --"), "{artifact} {flags:?}");
            assert!(!output.exists(), "{artifact} {flags:?}");
        }
    }
}

#[test]
fn public_check_export_is_explicit_type_only_and_another_pack_version() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let ordinary = root.join("ordinary");
    let public = root.join("public");
    let flags = ["--public-check"];
    for (directory, flags) in [(&ordinary, &[][..]), (&public, &flags[..])] {
        let result = export_with_flags(directory, "status", flags);
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    let pack_path = "adapter-packs/registry-status/pack.yaml";
    let source_path = "sources/registry-status.yaml";
    let facts_path = "adapter-packs/registry-status/schemas/facts.json";
    let inputs_path = "adapter-packs/registry-status/schemas/inputs.json";
    let read = |directory: &Path, relative| fs::read(directory.join(relative)).unwrap();
    let document = |directory: &Path, relative| -> Value {
        serde_norway::from_slice(&read(directory, relative)).unwrap()
    };
    let public_pack = document(&public, pack_path);
    let ordinary_pack = document(&ordinary, pack_path);
    assert_eq!(
        document(&public, source_path)["pack"]["version"],
        public_pack["version"]
    );
    assert_ne!(public_pack["version"], ordinary_pack["version"]);
    assert_eq!(public_pack["endpoints"], ordinary_pack["endpoints"]);
    let operation = |pack: &Value| pack["sourceRoutes"][0]["steps"][4].clone();
    assert_eq!(operation(&public_pack), operation(&ordinary_pack));
    assert_eq!(read(&public, inputs_path), read(&ordinary, inputs_path));
    assert_eq!(
        document(&public, facts_path),
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"status":{"type":"string"}},
            "required": []
        })
    );
    assert_ne!(read(&public, facts_path), read(&ordinary, facts_path));

    let repeat = root.join("repeat");
    assert!(export_with_flags(&repeat, "status", &flags)
        .status
        .success());
    assert_eq!(
        read(&public, "source-export.json"),
        read(&repeat, "source-export.json")
    );

    for rule in [
        ["--require-value", "status=active"],
        ["--optional-fields", "status"],
    ] {
        let refused = root.join("refused");
        let result = export_with_flags(
            &refused,
            "status",
            &flags.into_iter().chain(rule).collect::<Vec<_>>(),
        );
        assert!(!result.status.success());
        assert!(!refused.exists());
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            report["diagnostics"][0]["code"],
            "breg.evidence-source.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "public-check");
    }
}
