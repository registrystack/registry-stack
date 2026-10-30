#![allow(
    clippy::disallowed_methods,
    reason = "the test reads its generated report and package fixture; it reads no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use registry_breg::package::{
    prepare_package, PackageBuildRequest, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile,
};
use registry_breg::{compiler::module_digest, contract::parse_module_json};
use serde_json::{json, Value};
use tempfile::tempdir_in;

const FINDING_CODE: &str = "breg.manifest-projection.cross-dataset-reference-omitted";

const PROJECT: &[u8] = br#"{
  "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
  "kind":"BRegProject",
  "project":{
    "id":"manifest-omission",
    "version":"1",
    "defaultLanguage":"en",
    "canonicalBaseIri":"https://manifest-omission.example.test"
  },
  "package":{"sourceRevision":"manifest-omission-test"},
  "datasets":[{"id":"sources"},{"id":"targets"}],
  "manifestProjection":{
    "accessProfile":"reader",
    "classificationCeiling":"public",
    "catalog":{
      "baseUrl":"https://manifest-omission.example.test",
      "title":"Manifest omission",
      "publisher":{"id":"publisher","name":"Publisher"}
    },
    "publicService":{"id":"registry-service","title":"Registry service"},
    "datasets":[
      {"id":"sources","title":"Sources"},
      {"id":"targets","title":"Targets"}
    ],
    "dataServices":[{
      "id":"registry-api",
      "title":"Registry API",
      "endpointUrl":"https://manifest-omission.example.test/v1",
      "servesDatasets":["sources","targets"]
    }]
  },
  "recordTypes":[
    {
      "id":"source",
      "primaryDataset":"sources",
      "route":"sources",
      "mutationMode":"create-only",
      "classification":"public",
      "fields":[
        {
          "id":"code",
          "type":"string",
          "required":true,
          "minimumLength":1,
          "maximumLength":64,
          "classification":"public"
        },
        {
          "id":"status",
          "type":"string",
          "required":true,
          "maximumLength":64,
          "classification":"public"
        }
      ],
      "constraints":[{"type":"unique","fields":["code"]}],
      "selectorProfiles":[{"id":"by-code","fields":["code"]}]
    },
    {
      "id":"target",
      "primaryDataset":"targets",
      "route":"targets",
      "mutationMode":"create-only",
      "classification":"public",
      "fields":[{
        "id":"label",
        "type":"string",
        "maximumLength":64,
        "classification":"public"
      }]
    }
  ],
  "accessProfiles":[{
    "id":"reader",
    "principalClaim":"sub",
    "requiredScopes":["registry.read"],
    "permissions":{"records":[
      {
        "recordType":"source",
        "operations":["get","lookup"],
        "readableFields":["code","status","target"],
        "lookups":[{"selector":"by-code","valueOrigin":"request"}],
        "rowBoundaries":"unrestricted"
      },
      {
        "recordType":"target",
        "operations":["get"],
        "readableFields":["label"],
        "rowBoundaries":"unrestricted"
      }
    ]}
  }]
}"#;

const MODULE: &[u8] = br#"{
  "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
  "kind":"BRegModule",
  "id":"links",
  "version":"1",
  "extendRecordTypes":[{
    "recordType":"source",
    "fields":[{
      "id":"target",
      "type":"reference",
      "target":"target",
      "classification":"public"
    }]
  }]
}"#;

const JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys: []
"#;

#[test]
fn project_commands_report_the_same_positioned_manifest_omission_finding() {
    let current_directory = std::env::current_dir().expect("current directory is available");
    let temporary = tempdir_in(current_directory).expect("temporary directory is created");
    let project = temporary.path().join("project");
    fs::create_dir(&project).expect("project directory is created");
    let module = parse_module_json(MODULE).expect("module parses");
    let mut project_source: Value = serde_json::from_slice(PROJECT).expect("project parses");
    project_source["modules"] = json!([{
      "id":"links",
      "version":"1",
      "digest":module_digest(&module)
    }]);
    let project_bytes =
        serde_json::to_vec_pretty(&project_source).expect("project source serializes");
    fs::write(project.join("registry.yaml"), &project_bytes).expect("project source is written");
    let module_directory = project.join("modules/links");
    fs::create_dir_all(&module_directory).expect("module directory is created");
    let module_file = module_directory.join("module.yaml");
    fs::write(&module_file, MODULE).expect("module source is written");

    let package = temporary.path().join("package");
    prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: "manifest-omission-test".to_owned(),
        schema_fingerprint:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "links".to_owned(),
            path: "source/modules/links/module.yaml".to_owned(),
            bytes: MODULE.to_vec(),
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("baseline package prepares")
    .publish_to_directory(&package)
    .expect("baseline package publishes");

    let generated = temporary.path().join("generated");
    let evidence_source = temporary.path().join("evidence-source");
    let check = json_output(&bregctl(&["--format", "json", "check", path(&project)]));
    let lock = json_output(&bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(&project),
        "--check",
    ]));
    let diff = json_output(&bregctl(&[
        "--format",
        "json",
        "diff",
        path(&project),
        "--package",
        path(&package),
    ]));
    let generate = json_output(&bregctl(&[
        "--format",
        "json",
        "generate",
        "manifest",
        path(&project),
        "--output",
        path(&generated),
    ]));
    let generate_evidence_source = json_output(&bregctl(&[
        "--format",
        "json",
        "generate",
        "evidence-source",
        path(&project),
        "--access-profile",
        "reader",
        "--record-type",
        "source",
        "--selector",
        "by-code",
        "--fields",
        "status",
        "--source-id",
        "source-status",
        "--connection",
        "registry",
        "--output",
        path(&evidence_source),
    ]));

    let check_finding = one_finding(&check, "diagnostics");
    let lock_finding = one_finding(&lock, "diagnostics");
    let diff_finding = one_finding(&diff, "diagnostics");
    let generate_finding = one_finding(&generate, "diagnostics");
    let evidence_source_finding = one_finding(&generate_evidence_source, "diagnostics");
    for finding in [
        check_finding,
        lock_finding,
        diff_finding,
        generate_finding,
        evidence_source_finding,
    ] {
        assert_eq!(finding["code"], FINDING_CODE);
        assert_eq!(finding["path"], "/extendRecordTypes/0/fields/0");
        assert_eq!(finding["source"]["file"], path(&module_file));
        assert!(finding["source"]["line"]
            .as_u64()
            .is_some_and(|line| line > 0));
        assert!(finding["source"]["column"]
            .as_u64()
            .is_some_and(|column| column > 0));
        let message = finding["message"].as_str().expect("message is text");
        assert!(message.contains("different dataset"), "{finding}");
        assert!(message.contains("same projected dataset"), "{finding}");
    }
    assert_eq!(check_finding["source"], lock_finding["source"]);
    assert_eq!(check_finding["source"], diff_finding["source"]);
    assert_eq!(diff_finding["source"], generate_finding["source"]);
    assert_eq!(
        generate_finding["source"],
        evidence_source_finding["source"]
    );

    let denied = bregctl(&[
        "--format",
        "json",
        "check",
        path(&project),
        "--deny-warnings",
    ]);
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(denied.stderr.is_empty(), "{denied:?}");
    let denied: Value =
        serde_json::from_slice(&denied.stdout).expect("denied check output is JSON");
    assert_eq!(one_finding(&denied, "diagnostics")["code"], FINDING_CODE);
}

fn one_finding<'a>(report: &'a Value, member: &str) -> &'a Value {
    let findings = report[member]
        .as_array()
        .unwrap_or_else(|| panic!("{member} is an array: {report}"));
    let matching = findings
        .iter()
        .filter(|finding| finding["code"] == FINDING_CODE)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{member}: {report}");
    matching[0]
}

fn bregctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn json_output(output: &Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("command output is JSON")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}
