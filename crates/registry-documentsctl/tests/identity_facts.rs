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

/// A written starter project, and a runtime file whose `package.root` names
/// the package built from it. The runtime loader refuses a path through a
/// symbolic link, so the paths are canonical.
struct Starter {
    root: PathBuf,
    project: PathBuf,
    package: PathBuf,
    runtime: PathBuf,
}

impl Starter {
    fn new(root: &Path) -> Self {
        let root = std::fs::canonicalize(root).unwrap();
        let project = root.join("project");
        assert!(documentsctl(&["init", path(&project)]).status.success());
        Self {
            package: root.join("package"),
            runtime: root.join("runtime.yaml"),
            root,
            project,
        }
    }

    /// Rewrite `documents.yaml` by replacing `from` with `to`.
    fn edit_project(&self, from: &str, to: &str) {
        let source = self.project.join("documents.yaml");
        let text = std::fs::read_to_string(&source).unwrap();
        assert!(text.contains(from), "{from}");
        std::fs::write(&source, text.replace(from, to)).unwrap();
    }

    /// Build the package and write the runtime file, with `edit` applied to
    /// the runtime text. Returns the `package` command's output.
    fn build(&self, edit: impl FnOnce(String) -> String) -> Output {
        let built = documentsctl(&[
            "package",
            path(&self.project),
            "--output",
            path(&self.package),
        ]);
        let text = std::fs::read_to_string(self.project.join("runtime.example.yaml")).unwrap();
        let text = text.replace("/srv/registry-documents/package", path(&self.package));
        std::fs::write(&self.runtime, edit(text)).unwrap();
        built
    }

    fn generate(&self) -> (Output, PathBuf) {
        let output = self.root.join("facts.yaml");
        let run = documentsctl(&[
            "generate",
            "identity-facts",
            "--runtime-config",
            path(&self.runtime),
            "--output",
            path(&output),
        ]);
        (run, output)
    }
}

const GOLDEN: &str = "\
apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: documents
issuer: https://identity.example.test/realms/registry
audience: urn:example:documents
allowedClients:
- case-portal
- citizen-portal
- civil-registry-app
- partner-portal
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
- id: reader
  scopes:
  - documents:read
  requesterClients:
  - partner-portal
  actorKind: human
- id: staff
  scopes:
  - documents:staff
  requesterClients:
  - case-portal
  actorKind: human
";

#[test]
fn the_starter_states_its_issuer_clients_and_profiles_as_golden_facts() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    assert!(starter.build(|text| text).status.success());
    let (run, output) = starter.generate();
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert_eq!(
        stdout,
        format!(
            "created: {}\naccess profiles: 4\nclaims: 1\n",
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
    let starter = Starter::new(temporary.path());
    assert!(starter.build(|text| text).status.success());
    let output = starter.root.join("facts.yaml");
    std::fs::write(&output, "keep").unwrap();
    let (run, _) = starter.generate();
    assert!(!run.status.success());
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "keep");
}

#[test]
fn a_profile_client_the_runtime_does_not_admit_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    assert!(starter
        .build(|text| text.replace(
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]",
            "allowedClients: [civil-registry-app, citizen-portal, case-portal]",
        ))
        .status
        .success());
    let (run, output) = starter.generate();
    assert!(!run.status.success());
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("allowedClients"),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(!output.exists());
}

#[test]
fn assertion_issuers_are_refused_and_write_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    assert!(starter
        .build(|text| text.replace(
            "    scopeClaim: scope\n",
            "    scopeClaim: scope\n    assertionIssuers:\n      partner-portal: [https://assertions.example.test]\n",
        ))
        .status
        .success());
    let (run, output) = starter.generate();
    assert_eq!(run.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("assertion issuers"), "{stderr}");
    assert!(stderr.contains("the server runs"), "{stderr}");
    assert!(!output.exists());
}

#[test]
fn a_named_scope_claim_is_refused_and_writes_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    assert!(starter
        .build(|text| text.replace("scopeClaim: scope", "scopeClaim: registry_scopes"))
        .status
        .success());
    let (run, output) = starter.generate();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("scopeClaim"));
    assert!(!output.exists());
}

#[test]
fn a_profile_that_reads_its_principal_from_a_named_claim_requires_it_on_every_token() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    starter.edit_project(
        "  custodian-app:\n    principalClaim: sub",
        "  custodian-app:\n    principalClaim: service_account",
    );
    assert!(starter.build(|text| text).status.success());
    let (run, output) = starter.generate();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(facts.contains("  service_account: string\n"), "{facts}");
    assert!(
        facts.contains(
            "  requesterClients:\n  - civil-registry-app\n  actorKind: service\n  requiredClaims:\n  - service_account\n"
        ),
        "{facts}"
    );
}

#[test]
fn a_project_with_a_profile_sharing_every_scope_is_never_packaged_so_never_stated() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    starter.edit_project(
        "requiredScopes: [documents:staff]",
        "requiredScopes: [documents:read]",
    );
    let built = starter.build(|text| text);
    assert!(!built.status.success());
    let (run, output) = starter.generate();
    assert!(!run.status.success());
    assert!(!output.exists());
}

#[test]
fn a_standard_scope_name_is_refused_when_the_project_is_checked() {
    let temporary = tempfile::tempdir().unwrap();
    let starter = Starter::new(temporary.path());
    starter.edit_project(
        "requiredScopes: [documents:staff]",
        "requiredScopes: [openid]",
    );
    let checked = documentsctl(&["check", "--project", path(&starter.project)]);
    assert!(!checked.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(
        all.contains("documents.project.standard-scope-name"),
        "{all}"
    );
    let built = starter.build(|text| text);
    assert!(!built.status.success());
}
