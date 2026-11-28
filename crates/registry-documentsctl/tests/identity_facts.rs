// SPDX-License-Identifier: Apache-2.0

//! Public CLI contract for `documentsctl generate identity-facts`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn documentsctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_documentsctl"))
        .args(arguments)
        .output()
        .expect("documentsctl runs")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

/// The starter project and a runtime file written from the starter example.
/// The runtime loader refuses a path through a symbolic link, so the paths
/// are canonical.
fn starter(root: &Path) -> (PathBuf, PathBuf) {
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    assert!(documentsctl(&["init", path(&project)]).status.success());
    let runtime = root.join("runtime.yaml");
    std::fs::copy(project.join("runtime.example.yaml"), &runtime).unwrap();
    (project, runtime)
}

const MAIN_CLIENTS: &str =
    "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]";

/// The starter runtime with a second issuer entry that admits two of the
/// four package clients, and the first entry the other two.
fn two_issuers(runtime: &Path) {
    let text = std::fs::read_to_string(runtime).unwrap();
    assert!(text.contains(MAIN_CLIENTS));
    let text = text
        .replace(MAIN_CLIENTS, "allowedClients: [civil-registry-app, citizen-portal]")
        .replace(
            "    issuers:\n      main:\n",
            "    issuers:\n      partner:\n        issuer: https://partner.example.test\n        audience: urn:example:documents-partner\n        allowedClients: [case-portal, partner-portal]\n      main:\n",
        );
    std::fs::write(runtime, text).unwrap();
}

const GOLDEN_MAIN: &str = "\
apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: documents
issuer: https://identity.example.test/realms/registry
audience: urn:example:documents
allowedClients:
- citizen-portal
- civil-registry-app
claims:
  registry_actor_kind: string
accessProfiles:
- id: citizen
  scopes:
  - documents:own
  requesterClients:
  - citizen-portal
  actorKind: human
- id: custodian-app
  scopes:
  - documents:custody
  requesterClients:
  - civil-registry-app
  actorKind: service
";

#[test]
fn a_two_profile_issuer_states_its_clients_and_profiles_as_golden_facts() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    two_issuers(&runtime);
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
        "--issuer",
        "main",
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert_eq!(
        stdout,
        format!(
            "created: {}\naccess profiles: 2\nclaims: 1\n",
            path(&output)
        )
    );
    let facts = std::fs::read_to_string(&output).unwrap();
    assert_eq!(facts, GOLDEN_MAIN);
    // No local path and no secret reference reaches the document.
    for forbidden in [
        "/srv",
        "/run/",
        "secret:",
        temporary.path().to_str().unwrap(),
    ] {
        assert!(!facts.contains(forbidden), "facts carry {forbidden}");
    }
}

#[test]
fn a_missing_issuer_with_two_entries_is_refused_and_writes_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    two_issuers(&runtime);
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "--format",
        "json",
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert_eq!(run.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"],
        "identity.facts.issuer-required"
    );
    assert!(!output.exists());
}

#[test]
fn an_issuer_that_names_no_entry_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "--format",
        "json",
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
        "--issuer",
        "elsewhere",
    ]);
    assert_eq!(run.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"],
        "identity.facts.unknown-issuer"
    );
    assert!(!output.exists());
}

#[test]
fn a_single_entry_needs_no_issuer_and_states_every_package_profile() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let facts = std::fs::read_to_string(&output).unwrap();
    for profile in ["custodian-app", "citizen", "staff", "reader"] {
        assert!(facts.contains(&format!("- id: {profile}\n")), "{facts}");
    }
}

#[test]
fn an_existing_output_is_refused_and_left_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    std::fs::write(&output, "keep").unwrap();
    let run = documentsctl(&[
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert!(!run.status.success());
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "keep");
}

#[test]
fn a_profile_client_the_runtime_does_not_admit_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    std::fs::write(
        &runtime,
        text.replace(
            MAIN_CLIENTS,
            "allowedClients: [civil-registry-app, citizen-portal, case-portal]",
        ),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "--format",
        "json",
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert!(!run.status.success());
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"],
        "identity.facts.unstatable"
    );
    assert!(!output.exists());
}

#[test]
fn check_lists_the_explicit_settings_right_after_the_posture() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let text = std::fs::read_to_string(&runtime).unwrap().replace(
        MAIN_CLIENTS,
        &format!("{MAIN_CLIENTS}\n        accessTokenType: JWT"),
    );
    std::fs::write(&runtime, text).unwrap();
    let run = documentsctl(&[
        "--format",
        "json",
        "check",
        "--project",
        path(&project),
        "--runtime-config",
        path(&runtime),
    ]);
    let stdout = String::from_utf8(run.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        report["explicitProductionSettings"][0]["code"], "platform.posture.jwt-access-token",
        "{stdout}"
    );
    let at = |member: &str| stdout.find(&format!("\"{member}\"")).unwrap();
    assert!(at("posture") < at("explicitProductionSettings"), "{stdout}");
    assert!(
        at("explicitProductionSettings") < at("diagnostics"),
        "{stdout}"
    );
}

/// The runtime written from the starter, with `main` reading its clients
/// from the package and a second entry listing one client no profile names.
fn from_package_beside_a_list(runtime: &Path) {
    let text = std::fs::read_to_string(runtime).unwrap();
    let text = text
        .replace(MAIN_CLIENTS, "allowedClients: from-package")
        .replace(
            "    issuers:\n      main:\n",
            "    issuers:\n      batch:\n        issuer: https://batch.example.test\n        audience: urn:example:documents-batch\n        allowedClients: [batch-job]\n      main:\n",
        );
    std::fs::write(runtime, text).unwrap();
}

fn facts_of(project: &Path, runtime: &Path, issuer: &str) -> String {
    let output = runtime
        .parent()
        .unwrap()
        .join(format!("facts-{issuer}.yaml"));
    let run = documentsctl(&[
        "generate",
        "identity-facts",
        path(project),
        "--runtime-config",
        path(runtime),
        "--output",
        path(&output),
        "--issuer",
        issuer,
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    std::fs::read_to_string(&output).unwrap()
}

#[test]
fn each_entry_states_the_clients_it_admits_and_the_profiles_those_reach() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    from_package_beside_a_list(&runtime);
    let main = facts_of(&project, &runtime, "main");
    for client in [
        "civil-registry-app",
        "citizen-portal",
        "case-portal",
        "partner-portal",
    ] {
        assert!(main.contains(&format!("- {client}\n")), "{main}");
    }
    assert!(!main.contains("batch-job"), "{main}");
    let batch = facts_of(&project, &runtime, "batch");
    assert!(batch.contains("- batch-job\n"), "{batch}");
    assert!(!batch.contains("civil-registry-app"), "{batch}");
    assert!(!batch.contains("accessProfiles"), "{batch}");
}

#[test]
fn an_unknown_issuer_is_refused_without_repeating_the_value_given() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = documentsctl(&[
        "--format",
        "json",
        "generate",
        "identity-facts",
        path(&project),
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
        "--issuer",
        "canary-issuer-id",
    ]);
    assert_eq!(run.status.code(), Some(1));
    let stdout = String::from_utf8(run.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"],
        "identity.facts.unknown-issuer"
    );
    assert!(!stdout.contains("canary-issuer-id"), "{stdout}");
    assert!(!output.exists());
}

#[test]
fn check_reports_an_empty_list_for_a_read_file_and_none_for_one_never_decoded() {
    let temporary = tempfile::tempdir().unwrap();
    let (project, runtime) = starter(temporary.path());
    let check = |runtime: &Path| {
        let run = documentsctl(&[
            "--format",
            "json",
            "check",
            "--project",
            path(&project),
            "--runtime-config",
            path(runtime),
        ]);
        serde_json::from_slice::<serde_json::Value>(&run.stdout).unwrap()
    };
    let text = std::fs::read_to_string(&runtime).unwrap();
    // Read and refused by a product rule, with no setting stated.
    std::fs::write(
        &runtime,
        text.replace(MAIN_CLIENTS, "allowedClients: unrestricted"),
    )
    .unwrap();
    let refused = check(&runtime);
    assert_eq!(
        refused["explicitProductionSettings"],
        serde_json::json!([]),
        "{refused}"
    );
    // Never decoded: a removed key is refused by the reader.
    std::fs::write(
        &runtime,
        text.replace("    issuers:\n", "    scopeClaim: scp\n    issuers:\n"),
    )
    .unwrap();
    let undecoded = check(&runtime);
    assert!(
        undecoded.get("explicitProductionSettings").is_none(),
        "{undecoded}"
    );
}
