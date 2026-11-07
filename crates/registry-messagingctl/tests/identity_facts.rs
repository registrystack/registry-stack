// SPDX-License-Identifier: Apache-2.0

//! Public CLI contract for `messagingctl generate identity-facts`.

use std::path::Path;
use std::process::{Command, Output};

fn messagingctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_messagingctl"))
        .args(arguments)
        .output()
        .expect("messagingctl runs")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

/// A built starter package and a runtime file whose `package.root` names it.
/// The runtime loader refuses a path through a symbolic link, so the paths
/// are canonical.
fn starter(root: &Path) -> std::path::PathBuf {
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    assert!(messagingctl(&["init", path(&project)]).status.success());
    let package = root.join("package");
    let built = messagingctl(&["package", path(&project), "--output", path(&package)]);
    assert!(built.status.success());
    let runtime = root.join("runtime.yaml");
    let text = std::fs::read_to_string(project.join("runtime.example.yaml")).unwrap();
    std::fs::write(
        &runtime,
        text.replace("/srv/registry-messaging/package", path(&package)),
    )
    .unwrap();
    runtime
}

/// The starter with its `operations` profile reading the principal from a
/// named claim instead of the subject.
fn starter_with_named_principal(root: &Path) -> std::path::PathBuf {
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    assert!(messagingctl(&["init", path(&project)]).status.success());
    let source = project.join("messaging.yaml");
    let text = std::fs::read_to_string(&source).unwrap();
    let marker = "    principalClaim: sub\n    requiredScopes: [messaging:operate]\n";
    assert!(text.contains(marker));
    std::fs::write(
        &source,
        text.replace(
            marker,
            "    principalClaim: operator_id\n    requiredScopes: [messaging:operate]\n",
        ),
    )
    .unwrap();
    let package = root.join("package");
    let built = messagingctl(&["package", path(&project), "--output", path(&package)]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let runtime = root.join("runtime.yaml");
    let text = std::fs::read_to_string(project.join("runtime.example.yaml")).unwrap();
    std::fs::write(
        &runtime,
        text.replace("/srv/registry-messaging/package", path(&package)),
    )
    .unwrap();
    runtime
}

#[test]
fn a_profile_whose_principal_is_a_named_claim_requires_it_on_every_token() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = starter_with_named_principal(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = messagingctl(&[
        "generate",
        "identity-facts",
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
    assert!(facts.contains("  operator_id: string\n"), "{facts}");
    assert!(
        facts.ends_with(
            "- id: operations\n  scopes:\n  - messaging:operate\n  requesterClients:\n  - operations-console\n  requiredClaims:\n  - operator_id\n"
        ),
        "{facts}"
    );
    // The profile read by subject requires nothing beyond it.
    assert!(
        !facts.contains("actorKind: service\n  requiredClaims"),
        "{facts}"
    );
}

const GOLDEN: &str = "\
apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: messaging
issuer: https://identity.example.test/realms/registry
audience: urn:example:messaging
allowedClients:
- case-system
- operations-console
claims:
  registry_actor_kind: string
accessProfiles:
- id: case-notices
  scopes:
  - messaging:send
  requesterClients:
  - case-system
  actorKind: service
- id: operations
  scopes:
  - messaging:operate
  requesterClients:
  - operations-console
";

#[test]
fn the_starter_states_its_issuer_clients_and_profiles_as_golden_facts() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = messagingctl(&[
        "generate",
        "identity-facts",
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
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
    assert_eq!(facts, GOLDEN);
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
fn an_existing_output_is_refused_and_left_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    std::fs::write(&output, "keep").unwrap();
    let run = messagingctl(&[
        "generate",
        "identity-facts",
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
    let runtime = starter(temporary.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    std::fs::write(
        &runtime,
        text.replace(
            "allowedClients: [case-system, operations-console]",
            "allowedClients: [case-system]",
        ),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = messagingctl(&[
        "generate",
        "identity-facts",
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert!(!run.status.success());
    assert!(!output.exists());
}

fn facts_with_scope_claim(claim: &str) -> (bool, String) {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = starter(temporary.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    assert!(text.contains("# scopeClaim: registry_scopes"));
    std::fs::write(
        &runtime,
        text.replace(
            "# scopeClaim: registry_scopes",
            &format!("scopeClaim: {claim}"),
        ),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = messagingctl(&[
        "generate",
        "identity-facts",
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    let facts = std::fs::read_to_string(&output).unwrap_or_default();
    (run.status.success(), facts)
}

#[test]
fn a_custom_scope_claim_selects_each_profile_by_its_required_scopes() {
    let (ok, facts) = facts_with_scope_claim("registry_scopes");
    assert!(ok);
    assert!(
        facts.contains(
            "\nclaims:\n  registry_actor_kind: string\n  registry_scopes: string-array\n"
        ),
        "{facts}"
    );
    for (profile, scope) in [
        ("case-notices", "messaging:send"),
        ("operations", "messaging:operate"),
    ] {
        let expected = format!(
            "- id: {profile}\n  scopes:\n  - {scope}\n  requesterClients:\n  - {}\n  selectedBy:\n    registry_scopes:\n    - {scope}\n",
            if profile == "operations" { "operations-console" } else { "case-system" },
        );
        assert!(facts.contains(&expected), "{profile}\n{facts}");
    }
}

#[test]
fn the_default_scope_claim_states_no_selector() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = starter(temporary.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let run = messagingctl(&[
        "generate",
        "identity-facts",
        "--runtime-config",
        path(&runtime),
        "--output",
        path(&output),
    ]);
    assert!(run.status.success());
    assert!(!std::fs::read_to_string(&output)
        .unwrap()
        .contains("selectedBy"));
}

#[test]
fn a_reserved_scope_claim_is_refused_and_writes_nothing() {
    let (ok, facts) = facts_with_scope_claim("azp");
    assert!(!ok);
    assert!(facts.is_empty());
}
