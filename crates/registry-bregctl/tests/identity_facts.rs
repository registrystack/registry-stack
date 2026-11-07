// SPDX-License-Identifier: Apache-2.0

//! `bregctl generate identity-facts` states the issuer, audience, admitted
//! clients, claims and access profiles of one registry deployment.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const GOLDEN: &str = "\
apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: breg
issuer: https://issuer.example.invalid
audience: urn:example:generic-registry
allowedClients:
- generic-registry-client
claims:
  registry_actor_kind: string
  registry_principal: string
  registry_purpose: string
  registry_record_status: string
accessProfiles:
- id: evidence-source
  scopes:
  - registry:evidence:lookup
  purposes:
  - evidence-source-read
  requiredClaims:
  - registry_principal
- id: operator
  scopes:
  - registry:generic:operate
  purposes:
  - registry-operations
  requiredClaims:
  - registry_principal
- id: record-reader
  scopes:
  - registry:generic:read
  purposes:
  - registry-reporting
  requiredClaims:
  - registry_principal
  - registry_record_status
";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/fixtures/generic-operator-workflows")
}

/// A canonical scratch directory holding the fixture's runtime file with the
/// package and secret roots pointed at directories that exist.
fn runtime(root: &Path) -> PathBuf {
    let root = std::fs::canonicalize(root).unwrap();
    for directory in ["package", "secrets"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    let text = std::fs::read_to_string(fixture().join("runtime.example.yaml")).unwrap();
    // The facts format needs an audience that is an absolute URI; the
    // fixture's bare name is a valid runtime audience but not a valid fact.
    let text = text
        .replace(
            "audience: generic-registry\n",
            "audience: urn:example:generic-registry\n",
        )
        .replace(
            "/replace/me/secrets",
            root.join("secrets").to_str().unwrap(),
        )
        .replace(
            "/replace/me/packages/build-1/package",
            root.join("package").to_str().unwrap(),
        );
    let path = root.join("runtime.yaml");
    std::fs::write(&path, text).unwrap();
    path
}

fn generate(runtime: &Path, output: &Path) -> (bool, String, String) {
    generate_for(&fixture(), runtime, output)
}

fn generate_for(project: &Path, runtime: &Path, output: &Path) -> (bool, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            OsStr::new("bregctl"),
            OsStr::new("generate"),
            OsStr::new("identity-facts"),
            project.as_os_str(),
            OsStr::new("--runtime-config"),
            runtime.as_os_str(),
            OsStr::new("--output"),
            output.as_os_str(),
        ],
        &mut stdout,
        &mut stderr,
    );
    (
        status == std::process::ExitCode::SUCCESS,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn the_maintained_fixture_states_golden_facts_without_paths_or_secrets() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    assert_eq!(std::fs::read_to_string(&output).unwrap(), GOLDEN);
    let root = runtime.parent().unwrap().to_str().unwrap();
    for forbidden in [root, "/replace/me", "secret:", "audit.jsonl"] {
        let facts = std::fs::read_to_string(&output).unwrap();
        assert!(!facts.contains(forbidden), "facts carry {forbidden}");
    }
    assert!(stdout.contains("facts.yaml"), "{stdout}");
    assert!(!stdout.contains("registry:generic:operate"), "{stdout}");
}

#[test]
fn an_existing_output_is_refused_and_left_unchanged() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    std::fs::write(&output, "keep").unwrap();
    let (ok, _, _) = generate(&runtime, &output);
    assert!(!ok);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "keep");
}

#[test]
fn an_unrestricted_runtime_states_unrestricted_admission() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    std::fs::write(
        &runtime,
        text.replace(
            "allowedClients: [generic-registry-client]",
            "allowedClients: unrestricted",
        ),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    assert!(std::fs::read_to_string(&output)
        .unwrap()
        .contains("allowedClients: unrestricted"));
}

#[test]
fn a_customized_scope_claim_is_refused_and_writes_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let text = std::fs::read_to_string(&runtime).unwrap();
    assert!(text.contains("scopeClaim: scope\n"));
    std::fs::write(
        &runtime,
        text.replace("scopeClaim: scope\n", "scopeClaim: registry_scopes\n"),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(!ok);
    assert!(!output.exists());
    let text = format!("{stdout}{stderr}");
    assert!(text.contains("scopeClaim"), "{text}");
    assert!(text.contains("support yet"), "{text}");
}

/// A copy of the fixture project whose `evidence-source` profile requires
/// `kind` of whoever holds it. BReg requires the requester client beside it.
fn project_requiring(root: &Path, kind: &str) -> PathBuf {
    let project = root.join("project");
    copy_dir(&fixture(), &project);
    let path = project.join("registry.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let marker = "    requiredScopes: [registry:evidence:lookup]\n";
    assert!(text.contains(marker));
    let requester = "    requesterClients: [generic-registry-client]\n";
    std::fs::write(
        &path,
        text.replace(
            marker,
            &format!("{marker}{requester}    actorKind: {kind}\n"),
        ),
    )
    .unwrap();
    project
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Edit the runtime file in place.
fn edit_runtime(runtime: &Path, from: &str, to: &str) {
    let text = std::fs::read_to_string(runtime).unwrap();
    assert!(text.contains(from), "runtime lacks {from}");
    std::fs::write(runtime, text.replacen(from, to, 1)).unwrap();
}

const EVIDENCE_SOURCE: &str =
    "- id: evidence-source\n  scopes:\n  - registry:evidence:lookup\n  purposes:\n  - evidence-source-read\n";
/// The claims the fixture's `evidence-source` profile requires on every token.
const EVIDENCE_SOURCE_REQUIRED: &str = "  requiredClaims:\n  - registry_principal\n";

#[test]
fn a_profile_that_requires_a_kind_states_it_as_a_requirement() {
    for kind in ["human", "service"] {
        let scratch = tempfile::tempdir().unwrap();
        let runtime = runtime(scratch.path());
        let project = project_requiring(runtime.parent().unwrap(), kind);
        let output = runtime.parent().unwrap().join("facts.yaml");
        let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
        assert!(ok, "{kind}: {stdout}\n{stderr}");
        let expected = GOLDEN.replace(
            &format!("{EVIDENCE_SOURCE}{EVIDENCE_SOURCE_REQUIRED}"),
            &format!(
                "{EVIDENCE_SOURCE}  requesterClients:\n  - generic-registry-client\n  actorKind: {kind}\n{EVIDENCE_SOURCE_REQUIRED}"
            ),
        );
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            expected,
            "{kind}"
        );
    }
}

#[test]
fn an_agent_profile_is_left_out_and_named() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    // A runtime BReg starts with: an agent profile's requester client must be
    // a trusted actor.
    edit_runtime(
        &runtime,
        "    purpose: registry_purpose\n",
        "    purpose: registry_purpose\n    trustedActors:\n      generic-registry-client: 00000000-0000-4000-8000-000000000001\n",
    );
    let project = project_requiring(runtime.parent().unwrap(), "agent");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&output).unwrap(),
        GOLDEN.replace(&format!("{EVIDENCE_SOURCE}{EVIDENCE_SOURCE_REQUIRED}"), "")
    );
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("evidence-source"), "{report}");
    assert!(report.contains("delegated or task-grant token"), "{report}");
}

#[test]
fn a_profile_bound_by_different_claims_on_different_record_types_requires_each() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let project = runtime.parent().unwrap().join("project");
    copy_dir(&fixture(), &project);
    let path = project.join("registry.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let marker = "            - {field: status, claim: registry_record_status, operator: equals}\n";
    assert_eq!(text.matches(marker).count(), 1);
    let group = "        - recordType: record-group\n          operations: [get]\n          readableFields: [code]\n          rowBoundaries:\n            - {field: code, claim: registry_group_code, operator: equals}\n";
    std::fs::write(&path, text.replace(marker, &format!("{marker}{group}"))).unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(
        facts.ends_with(
            "  requiredClaims:\n  - registry_group_code\n  - registry_principal\n  - registry_record_status\n"
        ),
        "{facts}"
    );
}

#[test]
fn a_renamed_actor_kind_claim_is_refused_and_writes_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    edit_runtime(
        &runtime,
        "    purpose: registry_purpose\n",
        "    purpose: registry_purpose\n    contextual:\n      actorKind: registry_kind\n      purpose: registry_purpose\n      grantId: registry_grant_id\n      grantSourceIssuer: registry_grant_source_issuer\n      grantClient: registry_grant_client\n      grantResource: registry_grant_resource\n      grantExp: registry_grant_exp\n      grantBounds: registry_grant_bounds\n      approver: registry_approver\n",
    );
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("actorKind"), "{report}");
    assert!(report.contains("support yet"), "{report}");
}

#[test]
fn a_renamed_purpose_claim_is_refused_and_writes_nothing() {
    // Hosted generation derives and checks a principal's purpose only under
    // registry_purpose, so a token would never carry another name.
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    edit_runtime(
        &runtime,
        "    purpose: registry_purpose\n",
        "    purpose: purpose_of_use\n",
    );
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("authorityClaims.purpose"), "{report}");
    assert!(report.contains("support yet"), "{report}");
}

#[test]
fn a_profile_that_grants_only_an_action_is_stated_with_its_target_boundaries() {
    // `contact-registrar` grants one Action and no record type, so only the
    // Action surface states it; its targets are bound by `district`.
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/fixtures/household-contact-actions");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(
        facts.contains(
            "- id: contact-registrar\n  scopes:\n  - registry:contact:register\n  purposes:\n  - contact-registration\n  requiredClaims:\n  - district\n  - registry_principal\n"
        ),
        "{facts}"
    );
}

#[test]
fn a_verified_claim_lookup_requires_its_claim() {
    // BReg refuses the lookup when the token lacks the mapped claim, so the
    // profile states it.
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let project = runtime.parent().unwrap().join("project");
    copy_dir(&fixture(), &project);
    let path = project.join("registry.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let marker = "            - {selector: by-code, valueOrigin: request}\n";
    assert_eq!(text.matches(marker).count(), 1);
    let verified = "            - {selector: by-code, valueOrigin: verified-claim, claimMapping: {code: registry_record_code}}\n";
    std::fs::write(&path, text.replace(marker, verified)).unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(
        facts.contains(&format!(
            "{EVIDENCE_SOURCE}  requiredClaims:\n  - registry_principal\n  - registry_record_code\n"
        )),
        "{facts}"
    );
}

#[test]
fn a_row_boundary_on_a_boolean_or_integer_field_is_refused_and_writes_nothing() {
    // BReg reads such a claim as a JSON boolean or integer, and the hosted
    // generator issues every claim value as a string.
    for (kind, field_type) in [("boolean", "boolean"), ("int64", "int64")] {
        let scratch = tempfile::tempdir().unwrap();
        let runtime = runtime(scratch.path());
        let project = runtime.parent().unwrap().join("project");
        copy_dir(&fixture(), &project);
        let path = project.join("registry.yaml");
        let text = std::fs::read_to_string(&path).unwrap();
        let field_marker = "      - {id: status, type: vocabulary-code, vocabulary: record-status, classification: internal}\n";
        let boundary_marker =
            "            - {field: status, claim: registry_record_status, operator: equals}\n";
        assert_eq!(text.matches(field_marker).count(), 1);
        assert_eq!(text.matches(boundary_marker).count(), 1);
        let text = text
            .replace(
                field_marker,
                &format!("{field_marker}      - {{id: tier, type: {field_type}, classification: internal}}\n"),
            )
            .replace(
                boundary_marker,
                &format!("{boundary_marker}            - {{field: tier, claim: registry_record_tier, operator: equals}}\n"),
            );
        std::fs::write(&path, text).unwrap();
        let output = runtime.parent().unwrap().join("facts.yaml");
        let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
        assert!(!ok, "{kind}: {stdout}");
        assert!(
            stderr.contains("registry_record_tier")
                && stderr.contains("`record`")
                && stderr.contains("`tier`")
                && stderr.contains(kind),
            "{kind}: {stderr}"
        );
        assert!(!output.exists(), "{kind}");
    }
}
