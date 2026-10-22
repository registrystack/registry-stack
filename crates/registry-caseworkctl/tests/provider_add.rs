// SPDX-License-Identifier: Apache-2.0

//! Real public-CLI composition coverage. The Casework checkpoint supplies the
//! matching independently built `bregctl`; ordinary crate tests remain offline.

use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PATTERNS: [&str; 3] = [
    "single-reviewer-approval",
    "two-peer-approval",
    "technical-check-then-authorization",
];

#[path = "support/cli.rs"]
mod cli;
use cli::{caseworkctl, configure_library_path, dependency_directory};

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn read_yaml(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap();
    registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(&bytes)
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn bind_human_review_client(registry: &mut Value) {
    let reviewer = registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "proposal-reviewer")
        .unwrap();
    reviewer["actorKind"] = json!("human");
    reviewer["requesterClients"] = json!(["review-ui"]);
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .expect("generated project directory is readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("generated project entries are readable");
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("generated file type").is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).expect("generated file is readable"),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("copy destination exists");
    for entry in fs::read_dir(source).expect("copy source is readable") {
        let entry = entry.expect("copy source entry is readable");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("copy source type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy source file succeeds");
        }
    }
}

fn merge_object(target: &mut Value, patch: &Value) {
    let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) else {
        *target = patch.clone();
        return;
    };
    for (name, value) in patch {
        if name == "id" {
            continue;
        }
        if let Some(existing) = target.get_mut(name) {
            merge_object(existing, value);
        } else {
            target.insert(name.clone(), value.clone());
        }
    }
}

fn apply_authoring_suggestions(registry: &mut Value, changes: &[Value]) {
    for change in changes {
        let yaml = &change["yaml"];
        if let Some(actions) = yaml["actions"].as_array() {
            for patch in actions {
                let id = patch["id"].as_str().expect("suggested Action has an id");
                let action = registry["actions"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|action| action["id"].as_str() == Some(id))
                    .expect("suggested Action exists");
                merge_object(action, patch);
            }
        }
        for collection in ["reviewAuthorities", "accessProfiles"] {
            if let Some(entries) = yaml[collection].as_array() {
                let declared = registry[collection]
                    .as_array_mut()
                    .expect("suggested top-level collection exists");
                for patch in entries {
                    if let Some(existing) =
                        declared.iter_mut().find(|entry| entry["id"] == patch["id"])
                    {
                        merge_object(existing, patch);
                    } else {
                        declared.push(patch.clone());
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn external_caseworkctl_candidate_is_used() {
    const CHILD: &str = "REGISTRY_CASEWORKCTL_TEST_CANDIDATE";
    if std::env::var_os(CHILD).is_some() {
        let output = caseworkctl(&["--version"]);
        assert!(output.status.success());
        assert_eq!(
            output.stdout, b"candidate-selected-by-checkpoint\n",
            "integration tests must run the caller's CASEWORKCTL_BIN candidate"
        );
        return;
    }

    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let candidate = temporary.path().join("external caseworkctl");
    fs::write(
        &candidate,
        "#!/bin/sh\nprintf '%s\\n' 'candidate-selected-by-checkpoint'\n",
    )
    .unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "external_caseworkctl_candidate_is_used",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("CASEWORKCTL_BIN", candidate);
    configure_library_path(&mut child, &dependency_directory());
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "external candidate probe failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn real_bregctl_facility_generates_and_reruns_every_approval_pattern() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let bregctl = PathBuf::from(bregctl);
    let facility = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/facility")
        .canonicalize()
        .expect("facility example exists");
    let temporary = tempfile::tempdir().expect("temporary output exists");
    let temporary_path = temporary.path().canonicalize().unwrap();
    let bound_facility = temporary_path.join("facility");
    copy_tree(&facility, &bound_facility);
    let registry_path = bound_facility.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    bind_human_review_client(&mut registry);
    fs::write(registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let facility = bound_facility;

    for pattern in PATTERNS {
        let project = temporary_path.join(pattern);
        let output = caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            facility.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            pattern,
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "{pattern}: stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = json(&output);
        assert_eq!(report["ok"], true, "{pattern}: {report}");
        assert_eq!(report["data"]["state"], "created", "{pattern}: {report}");
        assert_eq!(
            report["data"]["providerId"], "correct-address-context",
            "{pattern}: {report}"
        );

        for arguments in [
            vec!["--format", "json", "check", project.to_str().unwrap()],
            vec![
                "--format",
                "json",
                "package",
                project.to_str().unwrap(),
                "--dry-run",
            ],
        ] {
            let checked = caseworkctl(&arguments);
            assert!(
                checked.status.success(),
                "{pattern}: {}",
                String::from_utf8_lossy(&checked.stderr)
            );
            assert_eq!(json(&checked)["ok"], true, "{pattern}");
        }

        let policy_path = project.join("casework.yaml");
        let mut authored = read_yaml(&policy_path);
        for policy in authored["reviewPolicies"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            for stage in policy["stages"].as_array_mut().unwrap() {
                let stage = stage.as_object_mut().unwrap();
                stage.entry("negativeDecisions").or_insert(json!("settle"));
                stage.entry("excludeInitiator").or_insert(json!(false));
                stage
                    .entry("excludePreviousStageReviewers")
                    .or_insert(json!(false));
            }
            for outcome in policy["outcomes"].as_object_mut().unwrap().values_mut() {
                outcome
                    .as_object_mut()
                    .unwrap()
                    .entry("resultRequired")
                    .or_insert(json!(false));
            }
        }
        fs::write(&policy_path, serde_norway::to_string(&authored).unwrap()).unwrap();
        let before = files(&project);
        let rerun = caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            facility.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            pattern,
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ]);
        assert!(
            rerun.status.success(),
            "{pattern}: {}",
            String::from_utf8_lossy(&rerun.stderr)
        );
        let report = json(&rerun);
        assert_eq!(
            report["data"]["state"], "in-agreement",
            "{pattern}: {report}"
        );
        assert_eq!(
            files(&project),
            before,
            "{pattern} rerun wrote project files"
        );
    }
}

#[test]
fn printed_authoring_fragments_compile_with_real_bregctl() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let bregctl = PathBuf::from(bregctl);
    for variant in [
        "bounded",
        "unrestricted",
        "existing-reviewer",
        "inputs-only",
        "reviewer-name-collision",
    ] {
        check_printed_authoring_fragments(&bregctl, variant);
    }
}

#[test]
fn unbound_reviewer_requires_a_human_client_binding() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let bregctl = PathBuf::from(bregctl);
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("facility");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/facility"),
        &source,
    );
    let project = root.join("review");
    let compose = || {
        caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            source.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ])
    };
    let before = files(&source);
    let first = compose();
    assert!(
        !first.status.success(),
        "an unbound profile is not a human reviewer binding"
    );
    let report = json(&first);
    assert_eq!(report["data"]["state"], "changes-needed");
    assert!(!project.exists());
    assert_eq!(files(&source), before);
    let changes = report["data"]["changes"].as_array().unwrap();
    let reviewer = changes
        .iter()
        .flat_map(|change| {
            change["yaml"]["accessProfiles"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .find(|profile| profile["actorKind"] == "human")
        .expect("the remedy binds a human review client");
    assert_ne!(
        reviewer["id"], "proposal-reviewer",
        "existing broad profiles are not narrowed implicitly"
    );
    assert!(!reviewer["requesterClients"].as_array().unwrap().is_empty());
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    apply_authoring_suggestions(&mut registry, changes);
    fs::write(registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let second = compose();
    assert!(
        second.status.success(),
        "the human-bound remedy compiles and composes"
    );
    assert_eq!(json(&second)["data"]["state"], "created");
    for (kind, client, admitted) in [
        (
            "human",
            reviewer["requesterClients"][0].as_str().unwrap(),
            true,
        ),
        (
            "service",
            reviewer["requesterClients"][0].as_str().unwrap(),
            false,
        ),
        ("human", "another-ui", false),
    ] {
        let scenario = root.join("reviewer-scenario.json");
        fs::write(
            &scenario,
            serde_json::to_vec(&json!({
                "recordType":"facility", "accessProfile":reviewer["id"], "operation":"get",
                "claims":{
                    "actorKind":kind, "requesterClient":client,
                    "principalClaim":reviewer["principalClaim"], "principal":"synthetic-reviewer",
                    "scopes":reviewer["requiredScopes"], "purpose":"registry-review",
                    "directClaims":{"jurisdiction":"synthetic-jurisdiction"}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mut preview = Command::new(&bregctl);
        preview
            .args(["--format", "json", "explain", "access"])
            .arg(&source)
            .arg("--scenario")
            .arg(&scenario);
        configure_library_path(&mut preview, &dependency_directory());
        let result = preview.output().unwrap();
        let report = json(&result);
        assert_eq!(report["explanation"]["admitted"], admitted, "{report}");
    }
}

#[test]
fn record_backed_context_includes_the_referenced_proposal_target() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    for variant in [
        "record-reference",
        "reference-input-only",
        "unprojected-reference",
    ] {
        check_printed_authoring_fragments(Path::new(&bregctl), variant);
    }
}

#[test]
fn encrypted_writes_require_an_explicit_supported_review_context() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    check_printed_authoring_fragments(Path::new(&bregctl), "encrypted-write");
}

#[test]
fn requirement_inputs_are_disclosed_in_generated_review_contexts() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    check_printed_authoring_fragments(Path::new(&bregctl), "requirement-input");
}

#[test]
fn oversized_default_contexts_require_explicit_minimized_contexts() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    for variant in ["oversized-context", "oversized-changes"] {
        check_printed_authoring_fragments(Path::new(&bregctl), variant);
    }
}

fn check_printed_authoring_fragments(bregctl: &Path, variant: &str) {
    let facility = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/facility")
        .canonicalize()
        .expect("facility example exists");
    let temporary = tempfile::tempdir().expect("temporary output exists");
    let temporary_path = temporary.path().canonicalize().unwrap();
    let incomplete = temporary_path.join("facility");
    copy_tree(&facility, &incomplete);
    let registry_path = incomplete.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    registry["reviewAuthorities"] = json!([]);
    registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .retain(|profile| {
            profile["id"] != "casework-review-status"
                && (matches!(
                    variant,
                    "existing-reviewer"
                        | "record-reference"
                        | "reference-input-only"
                        | "unprojected-reference"
                ) || profile["id"] != "proposal-reviewer")
        });
    if matches!(
        variant,
        "existing-reviewer" | "record-reference" | "reference-input-only" | "unprojected-reference"
    ) {
        let reviewer = registry["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|profile| profile["id"] == "proposal-reviewer")
            .unwrap();
        reviewer["requiredScopes"] = json!("unrestricted");
        reviewer["actorKind"] = json!("human");
        reviewer["requesterClients"] = json!(["review-ui"]);
        reviewer.as_object_mut().unwrap().remove("requiredPurposes");
        reviewer["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("records");
    }
    if matches!(
        variant,
        "record-reference" | "reference-input-only" | "unprojected-reference"
    ) {
        for collection in ["actions", "proposals"] {
            for permission in registry["accessProfiles"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .filter_map(|profile| {
                    profile
                        .get_mut("permissions")?
                        .get_mut(collection)?
                        .as_array_mut()
                })
                .flatten()
                .filter(|permission| permission["action"] == "correct-address")
            {
                permission["targets"].as_array_mut().unwrap().push(json!({
                    "recordType":"operator",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
                }));
            }
        }
    }
    if variant == "encrypted-write" {
        let field = registry["recordTypes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["id"] == "facility")
            .unwrap()["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|field| field["id"] == "address-line")
            .unwrap();
        field["classification"] = json!("restricted");
        field["encrypted"] = json!(true);
    }
    if variant == "oversized-changes" {
        let fields = registry["recordTypes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["id"] == "facility")
            .unwrap()["fields"]
            .as_array_mut()
            .unwrap();
        for index in 0..62 {
            fields.push(json!({
                "id":format!("extra-{index}"), "type":"string",
                "maximumLength":8, "classification":"internal"
            }));
        }
    }
    if variant == "reviewer-name-collision" {
        registry["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"correct-address-reviewer", "actorKind":"service",
                "requesterClients":["existing-service"], "principalClaim":"registry_principal",
                "requiredScopes":["registry:directory:read"],
                "permissions":{"records":[{
                    "recordType":"directory-entry", "operations":["get"],
                    "readableFields":["name"], "rowBoundaries":"unrestricted"
                }]}
            }));
    }
    if variant == "unrestricted" {
        for permission in registry["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter_map(|profile| {
                profile
                    .get_mut("permissions")?
                    .get_mut("actions")?
                    .as_array_mut()
            })
            .flatten()
            .filter(|permission| permission["action"] == "correct-address")
        {
            for target in permission["targets"].as_array_mut().unwrap() {
                target["rowBoundaries"] = json!("unrestricted");
            }
        }
    }
    let action = registry["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "correct-address")
        .unwrap();
    if variant == "requirement-input" {
        action["inputs"].as_array_mut().unwrap().push(json!({
            "id":"expected-address", "typeRef":"address-line",
            "required":true, "classification":"internal"
        }));
        action["commitGuards"]["targets"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "input":"facility", "field":"address-line",
                "equalsFromInput":"expected-address"
            }));
    }
    if variant == "oversized-context" {
        for index in 0..60 {
            let input = format!("extra-{index}");
            action["inputs"].as_array_mut().unwrap().push(json!({
                "id":input, "type":"string", "maximumLength":8,
                "required":true, "classification":"internal"
            }));
            action["plan"]["inputs"]
                .as_array_mut()
                .unwrap()
                .push(json!(input));
        }
    }
    if variant == "oversized-changes" {
        for index in 0..62 {
            action["plan"]["writes"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("extra-{index}")));
        }
    }
    action["execution"]["proposal"]["review"] = json!({"type":"none"});
    if variant == "inputs-only" {
        action["execution"]["proposal"]["reviewContext"]["fields"]
            .as_object_mut()
            .unwrap()
            .retain(|_, field| field["type"] == "input");
    } else if matches!(
        variant,
        "record-reference" | "reference-input-only" | "unprojected-reference"
    ) {
        action["inputs"].as_array_mut().unwrap().push(json!({
            "id":"operator", "type":"reference", "target":"operator",
            "required":true, "classification":"internal"
        }));
        let fields = &mut action["execution"]["proposal"]["reviewContext"]["fields"];
        if variant == "record-reference" {
            fields["operatorCode"] =
                json!({"type":"record","input":"operator","field":"operator-code"});
        } else if variant == "reference-input-only" {
            fields["operatorId"] = json!({"type":"input","input":"operator"});
        }
    } else if variant != "existing-reviewer" {
        action["execution"]["proposal"]
            .as_object_mut()
            .unwrap()
            .remove("reviewContext");
    }
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();

    let mut source_check = Command::new(bregctl);
    source_check
        .args(["--format", "json", "check"])
        .arg(&incomplete);
    configure_library_path(&mut source_check, &dependency_directory());
    let checked = source_check.output().unwrap();
    assert!(
        checked.status.success(),
        "{variant} source fixture must compile before composition: stdout={}; stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );

    let casework = temporary_path.join("review");
    let compose = || {
        caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            casework.to_str().unwrap(),
            "--breg-project",
            incomplete.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ])
    };
    let before = files(&incomplete);
    let mut first = compose();
    if matches!(
        variant,
        "encrypted-write" | "oversized-context" | "oversized-changes"
    ) {
        assert!(!first.status.success());
        let refusal = json(&first);
        let expected = if variant == "encrypted-write" {
            "casework.provider-add.encrypted-review-context"
        } else {
            "casework.provider-add.review-context-bounds"
        };
        assert_eq!(refusal["diagnostics"][0]["code"], expected, "{refusal}");
        assert_eq!(files(&incomplete), before);
        assert!(!casework.exists());
        let action = registry["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap();
        action["execution"]["proposal"]["reviewContext"] = json!({
            "id":"explicit-address-context",
            "fields":{"addressLine":{"type":"input","input":"address-line"}}
        });
        fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
        first = compose();
    }
    assert_eq!(
        first.status.code(),
        Some(1),
        "stdout={}; stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first = json(&first);
    assert_eq!(
        first["diagnostics"][0]["code"], "casework.provider-add.breg-changes-needed",
        "{variant}: {first}"
    );
    if variant == "requirement-input" {
        let proposed = first["data"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|change| change["yaml"]["actions"].as_array().into_iter().flatten())
            .find_map(|action| {
                action["execution"]["proposal"]["reviewContext"]["fields"].as_object()
            })
            .expect("missing review context has a proposed field mapping");
        assert!(
            proposed
                .values()
                .any(|field| field["input"] == "expected-address"),
            "reviewers must see an input used only by a precondition comparison: {first}"
        );
        let alternative = &first["data"]["inputsOnlyAlternative"]["yaml"]["actions"][0]
            ["execution"]["proposal"]["reviewContext"]["fields"];
        assert!(alternative
            .as_object()
            .unwrap()
            .values()
            .any(|field| { field["input"] == "expected-address" }));
    }
    if variant == "reviewer-name-collision" {
        assert!(
            first["data"]["changes"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|change| change["yaml"]["accessProfiles"]
                    .as_array()
                    .into_iter()
                    .flatten())
                .all(|profile| profile["id"] != "correct-address-reviewer"),
            "generated reviewer authority must not reuse an unrelated service profile"
        );
    }
    if matches!(
        variant,
        "record-reference" | "reference-input-only" | "unprojected-reference"
    ) {
        let reviewer = first["data"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|change| {
                change["yaml"]["accessProfiles"]
                    .as_array()
                    .into_iter()
                    .flatten()
            })
            .find(|profile| profile["id"] == "proposal-reviewer")
            .expect("the existing reviewer receives the missing context authority");
        assert!(
            reviewer["permissions"]["proposals"][0]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|target| target["recordType"] == "operator"),
            "referenced inputs need their own Proposal target authority"
        );
        assert_eq!(
            reviewer["permissions"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["recordType"] == "operator"),
            variant == "record-reference",
            "only record-backed context needs records.get on the referenced type"
        );
    }
    apply_authoring_suggestions(&mut registry, first["data"]["changes"].as_array().unwrap());
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();

    let mut check_command = Command::new(bregctl);
    check_command
        .args(["--format", "json", "check"])
        .arg(&incomplete);
    configure_library_path(&mut check_command, &dependency_directory());
    let checked = check_command.output().expect("bregctl check starts");
    assert!(
        checked.status.success(),
        "printed BReg fragments did not compile for {variant}: stdout={} stderr={}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(json(&checked)["ok"], true);

    let second = caseworkctl(&[
        "--format",
        "json",
        "provider",
        "add",
        casework.to_str().unwrap(),
        "--breg-project",
        incomplete.to_str().unwrap(),
        "--action",
        "correct-address",
        "--pattern",
        "single-reviewer-approval",
        "--bregctl-bin",
        bregctl.to_str().unwrap(),
    ]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(json(&second)["data"]["state"], "created");
}

#[test]
fn real_bregctl_preserves_broad_source_namespace_behind_local_bindings() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let bregctl = PathBuf::from(bregctl);
    let facility = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/facility")
        .canonicalize()
        .expect("facility example exists");
    let temporary = tempfile::tempdir().expect("temporary output exists");
    let temporary_path = temporary.path().canonicalize().unwrap();
    let source = temporary_path.join("facility");
    copy_tree(&facility, &source);
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    bind_human_review_client(&mut registry);
    let action = registry["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "correct-address")
        .unwrap();
    action["execution"]["proposal"]["review"]["source"] = json!("facility.registry:v1");
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();

    let project = temporary_path.join("review");
    let output = caseworkctl(&[
        "--format",
        "json",
        "provider",
        "add",
        project.to_str().unwrap(),
        "--breg-project",
        source.to_str().unwrap(),
        "--action",
        "correct-address",
        "--pattern",
        "single-reviewer-approval",
        "--bregctl-bin",
        bregctl.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        json(&output)["data"]["sourceNamespace"],
        "facility.registry:v1"
    );
    let authored = read_yaml(&project.join("casework.yaml"));
    assert_eq!(
        authored["contextProviders"]["correct-address-context"]["sourceNamespace"],
        "facility.registry:v1"
    );
    assert_eq!(
        authored["contextProviders"]["correct-address-context"]["deploymentRef"],
        "correct-address-context"
    );
    assert_eq!(
        authored["trustedProducers"]["correct-address-review-producer"]["sourceNamespaces"],
        json!(["facility.registry:v1"])
    );
    assert!(authored["trustedProducers"]
        .get("facility.registry:v1")
        .is_none());
    let runtime = read_yaml(&project.join("runtime.example.yaml"));
    assert!(runtime["contextProviders"]
        .get("correct-address-context")
        .is_some());
    assert!(runtime["contextProviders"]
        .get("facility.registry:v1")
        .is_none());
}

#[test]
fn exact_policy_selection_matches_the_generated_and_existing_policy() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let bregctl = PathBuf::from(bregctl);
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("facility");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/facility"),
        &source,
    );
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    bind_human_review_client(&mut registry);
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let compose = |project: &Path| {
        caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            source.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ])
    };
    let existing = root.join("existing");
    let first = compose(&existing);
    assert!(first.status.success(), "{}", json(&first));
    let explained = caseworkctl(&["--format", "json", "explain", existing.to_str().unwrap()]);
    assert!(explained.status.success(), "{}", json(&explained));
    let binding = json(&explained)["data"]["reviewPolicies"][0]["binding"].clone();
    assert!(binding["digest"].as_str().is_some());

    for variant in ["matching", "wrong-version", "wrong-digest"] {
        let mut selected = binding.clone();
        if variant == "wrong-version" {
            selected["version"] = json!("99");
        } else if variant == "wrong-digest" {
            selected["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
        }
        registry["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["review"]["policy"] = selected;
        fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
        let mut check = Command::new(&bregctl);
        check.args(["--format", "json", "check"]).arg(&source);
        configure_library_path(&mut check, &dependency_directory());
        let checked = check.output().unwrap();
        assert!(checked.status.success(), "{variant}: {}", json(&checked));

        let source_before = files(&source);
        let existing_before = files(&existing);
        let created = root.join(variant);
        for destination in [&created, &existing] {
            let output = compose(destination);
            let report = json(&output);
            if variant == "matching" {
                assert!(output.status.success(), "{variant}: {report}");
                assert_eq!(
                    report["data"]["state"],
                    if destination == &existing {
                        "in-agreement"
                    } else {
                        "created"
                    },
                    "{report}"
                );
            } else {
                assert!(
                    !output.status.success(),
                    "an exact policy pin must match the policy Casework will accept: {report}"
                );
                assert_eq!(
                    report["diagnostics"][0]["code"],
                    "casework.provider-add.policy-binding-mismatch",
                    "{report}"
                );
                assert!(
                    !created.exists(),
                    "a refused policy pin leaves no new project"
                );
            }
        }
        assert_eq!(
            files(&source),
            source_before,
            "{variant} rewrote BReg source"
        );
        assert_eq!(
            files(&existing),
            existing_before,
            "{variant} rewrote the existing project"
        );
    }
}

#[test]
fn reruns_revalidate_required_runtime_scopes_without_rewriting_operator_bindings() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("facility");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/facility"),
        &source,
    );
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    bind_human_review_client(&mut registry);
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let project = root.join("review");
    let compose = || {
        caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            source.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ])
    };
    let created = compose();
    assert!(created.status.success(), "{}", json(&created));
    let before = files(&project);
    let status = registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "casework-review-status")
        .unwrap();
    status["requiredScopes"] =
        json!(["registry:proposal:review-status", "registry:status:updated"]);
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let refused = compose();
    assert!(
        !refused.status.success(),
        "stale runtime scopes must not report agreement: {}",
        json(&refused)
    );
    assert_eq!(
        json(&refused)["diagnostics"][0]["code"],
        "casework.provider-add.existing-project-mismatch"
    );
    assert!(json(&refused)["diagnostics"][0]["path"]
        .as_str()
        .unwrap()
        .contains("scopes"));
    assert_eq!(files(&project), before);

    let runtime_path = project.join("runtime.example.yaml");
    let mut runtime = read_yaml(&runtime_path);
    runtime["contextProviders"]["correct-address-context"]["scopes"] = json!([
        "registry:status:updated",
        "operator:extra",
        "registry:proposal:review-status"
    ]);
    fs::write(&runtime_path, serde_norway::to_string(&runtime).unwrap()).unwrap();
    let updated = files(&project);
    let agreed = compose();
    assert!(
        agreed.status.success(),
        "required scopes may be reordered and augmented: {}",
        json(&agreed)
    );
    assert_eq!(json(&agreed)["data"]["state"], "in-agreement");
    assert_eq!(files(&project), updated);

    let status = registry["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "casework-review-status")
        .unwrap();
    status["requiredScopes"] = json!("unrestricted");
    fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
    let agreed = compose();
    assert!(
        agreed.status.success(),
        "an unrestricted source accepts the operator's configured scopes: {}",
        json(&agreed)
    );
    assert_eq!(files(&project), updated);
}

#[test]
fn external_policy_ids_receive_an_actionable_local_compatibility_refusal() {
    let Some(bregctl) = std::env::var_os("BREGCTL_BIN") else {
        eprintln!("skipped: set BREGCTL_BIN to the matching independently built bregctl");
        return;
    };
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let source = root.join("facility");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/facility"),
        &source,
    );
    let registry_path = source.join("registry.yaml");
    let mut registry = read_yaml(&registry_path);
    bind_human_review_client(&mut registry);
    for (index, policy_id) in [
        "urn:example:review".to_owned(),
        "a".repeat(65),
        "a".repeat(64),
    ]
    .into_iter()
    .enumerate()
    {
        registry["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["review"]["policy"]["id"] = json!(policy_id);
        fs::write(&registry_path, serde_norway::to_string(&registry).unwrap()).unwrap();
        let source_before = files(&source);
        let project = root.join(format!("review-{index}"));
        let result = caseworkctl(&[
            "--format",
            "json",
            "provider",
            "add",
            project.to_str().unwrap(),
            "--breg-project",
            source.to_str().unwrap(),
            "--action",
            "correct-address",
            "--pattern",
            "single-reviewer-approval",
            "--bregctl-bin",
            bregctl.to_str().unwrap(),
        ]);
        let report = json(&result);
        if index < 2 {
            assert!(!result.status.success(), "{report}");
            assert_eq!(
                report["diagnostics"][0]["code"], "casework.provider-add.policy-id-unsupported",
                "an external policy ID must receive a specific compatibility remedy: {report}"
            );
            assert!(!project.exists());
        } else {
            assert!(
                result.status.success(),
                "the maximum valid Casework policy ID is supported: {report}"
            );
            assert_eq!(report["data"]["policyId"], policy_id);
            assert!(read_yaml(&project.join("casework.yaml"))["reviewPolicies"]
                .get(&policy_id)
                .is_some());
        }
        assert_eq!(files(&source), source_before);
    }
}
