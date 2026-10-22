// SPDX-License-Identifier: Apache-2.0
//! The status service must not inherit any statistical dataset authority.

#![cfg(unix)]

#[path = "support/cli.rs"]
mod cli;

use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn explanation(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/formats/explain")
        .join(format!("{name}-explanation.json"));
    let mut explanation: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    // This fixture varies the service's statistical authority; its human
    // reviewer must independently satisfy the current actor/client contract.
    for action in explanation["actions"].as_array_mut().into_iter().flatten() {
        for permission in action["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            if permission["profileId"] == "proposal-reviewer" {
                permission["actorKind"] = json!("human");
                permission["requesterClients"] = json!(["review-ui"]);
            }
        }
    }
    explanation
}

fn write_report(root: &Path, name: &str, explanation: &Value) {
    fs::write(
        root.join(format!("{name}.json")),
        serde_json::to_vec(&json!({"ok": true, "explanation": explanation})).unwrap(),
    )
    .unwrap();
}

#[test]
fn poc_f003_status_service_has_no_statistical_dataset_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let fake = root.join("bregctl");
    for name in ["proposals", "actions", "access"] {
        write_report(&root, name, &explanation(name));
    }
    fs::write(
        root.join("version"),
        registry_platform_buildinfo::DISPLAY_VERSION,
    )
    .unwrap();
    let schema_bytes = include_bytes!(
        "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
    );
    let schema: Value = serde_json::from_slice(schema_bytes).unwrap();
    fs::write(root.join("schema.json"), schema_bytes).unwrap();
    fs::write(
        root.join("index.json"),
        serde_json::to_vec(&json!({"correct-address": {
            "id": schema["$id"],
            "revision": schema["x-registry-definition-revision"],
            "digest": registry_platform_config::sha256_uri(schema_bytes),
            "path": "generated/review-context-schemas/correct-address.schema.json"
        }}))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &fake,
        r#"#!/bin/sh
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$1" = "--version" ]; then
  printf 'bregctl '
  cat "$fixture/version"
  printf '\n'
  exit 0
fi
if [ "$3" = "explain" ]; then
  case "$4" in
    proposals|actions|access) exec cat "$fixture/$4.json" ;;
  esac
fi
if [ "$3" = "generate" ] && [ "$4" = "schemas" ]; then
  while [ "$#" -gt 0 ] && [ "$1" != "--output" ]; do shift; done
  [ "$#" -gt 1 ] || exit 1
  output=$2
  mkdir -p "$output/generated/review-context-schemas"
  cp "$fixture/index.json" "$output/generated/review-context-schemas/index.json"
  cp "$fixture/schema.json" "$output/generated/review-context-schemas/correct-address.schema.json"
  printf '%s\n' '{"ok":true}'
  exit 0
fi
exit 1
"#,
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();

    for operation in [
        None,
        Some("readLive"),
        Some("publish"),
        Some("readReleases"),
    ] {
        let mut access = explanation("access");
        if let Some(operation) = operation {
            let mut dataset = json!({
                "dataset": "facility-counts",
                "accessProfiles": [],
                "readLive": [],
                "publish": [],
                "readReleases": []
            });
            dataset[operation] = json!(["casework-review-status"]);
            access["statisticalDatasets"] = json!([dataset]);
        }
        write_report(&root, "access", &access);
        let project = root.join(operation.unwrap_or("status-only"));
        let output = cli::caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            root.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            fake.to_str().unwrap(),
        ]);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid CLI report: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        if let Some(operation) = operation {
            assert_eq!(
                report["data"]["state"], "changes-needed",
                "a service with {operation} statistical authority must not be accepted as status-only: {report}"
            );
            assert!(
                !project.exists(),
                "an overprivileged status service must not produce a project"
            );
            let changes = report["data"]["changes"].as_array().unwrap();
            assert!(
                changes.iter().any(|change| {
                    change["path"] == "accessProfiles[id=correct-address-review-status]"
                        && change["yaml"]["accessProfiles"][0]["permissions"]["proposals"][0]
                            ["operations"]
                            == json!(["get-review-status"])
                }),
                "the remedy must propose a purpose-specific status profile: {report}"
            );
        } else {
            assert!(
                output.status.success(),
                "a genuine status-only service must remain usable: {report}"
            );
            assert_eq!(report["data"]["state"], "created", "{report}");
        }
    }
}
