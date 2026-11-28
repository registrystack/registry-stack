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

/// The facts file `path`, read back through the facts reader.
fn read_facts(path: &Path) -> registry_thunderid_tooling::identity_facts::IdentityFacts {
    let bytes = std::fs::read(path).unwrap();
    registry_thunderid_tooling::identity_facts::read("facts", &bytes).unwrap()
}

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
    generate_with(project, runtime, output, &[])
}

/// Run the command with `extra` arguments after the required ones.
fn generate_with(
    project: &Path,
    runtime: &Path,
    output: &Path,
    extra: &[&str],
) -> (bool, String, String) {
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
        ]
        .into_iter()
        .chain(extra.iter().map(OsStr::new)),
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
fn a_customized_scope_claim_is_declared_as_an_array_claim() {
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
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(
        facts.contains("  registry_scopes: string-array\n"),
        "{facts}"
    );
}

#[test]
fn the_default_scope_claim_is_not_declared() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = read_facts(&output);
    assert!(!facts.claims.contains_key("scope"), "{:?}", facts.claims);
    assert!(facts
        .access_profiles
        .iter()
        .all(|profile| profile.selected_by.is_empty()));
}

#[test]
fn a_scope_claim_that_names_a_reserved_token_claim_is_refused_and_writes_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    edit_runtime(&runtime, "scopeClaim: scope\n", "scopeClaim: client_id\n");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("scopeClaim"), "{report}");
    assert!(report.contains("reserved"), "{report}");
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
fn a_scopeless_agent_profile_still_generates_facts() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    edit_runtime(
        &runtime,
        "    purpose: registry_purpose\n",
        "    purpose: registry_purpose\n    trustedActors:\n      generic-registry-client: 00000000-0000-4000-8000-000000000001\n",
    );
    let project = project_requiring(runtime.parent().unwrap(), "agent");
    let registry = project.join("registry.yaml");
    let text = std::fs::read_to_string(&registry).unwrap();
    let scoped = "    requiredScopes: [registry:evidence:lookup]\n";
    assert!(text.contains(scoped));
    std::fs::write(
        &registry,
        text.replace(scoped, "    requiredScopes: unrestricted\n"),
    )
    .unwrap();
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(!facts.contains("id: evidence-source"), "{facts}");
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
fn a_renamed_actor_kind_claim_is_refused_naming_the_setting_and_writes_nothing() {
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
    assert!(report.contains("identity-facts.unstatable"), "{report}");
    assert!(
        report.contains("authentication.authorityClaims.contextual.actorKind"),
        "{report}"
    );
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

/// The runtime with a second issuer entry, `partners`, beside `primary`.
fn two_issuer_runtime(root: &Path) -> PathBuf {
    let runtime = runtime(root);
    edit_runtime(
        &runtime,
        "  authorityClaims:\n",
        "      partners:\n        issuer: https://partners.example.invalid\n        audience: urn:example:partners\n        allowedAlgorithm: ES256\n        scopeSeparator: \" \"\n        allowedClients: [partner-client]\n        maximumTokenLifetimeSeconds: 300\n        leewayMilliseconds: 30000\n        jwksSource:\n          type: discovery\n  authorityClaims:\n",
    );
    runtime
}

#[test]
fn two_entries_without_an_issuer_are_refused_and_write_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = two_issuer_runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(
        report.contains("identity.facts.issuer-required"),
        "{report}"
    );
    assert!(report.contains("--issuer"), "{report}");
    assert!(!report.contains("issuer.example.invalid"), "{report}");
}

#[test]
fn an_issuer_that_names_no_entry_is_refused_and_writes_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = two_issuer_runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) =
        generate_with(&fixture(), &runtime, &output, &["--issuer", "missing"]);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("identity.facts.unknown-issuer"), "{report}");
}

#[test]
fn a_named_issuer_states_the_facts_of_that_entry() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = two_issuer_runtime(scratch.path());
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) =
        generate_with(&fixture(), &runtime, &output, &["--issuer", "partners"]);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(
        facts.contains("issuer: https://partners.example.invalid\n"),
        "{facts}"
    );
    assert!(
        facts.contains("audience: urn:example:partners\n"),
        "{facts}"
    );
    assert!(facts.contains("- partner-client\n"), "{facts}");
    assert!(!facts.contains("generic-registry-client"), "{facts}");
}

#[test]
fn one_entry_needs_no_issuer_and_may_be_named() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let unnamed = runtime.parent().unwrap().join("unnamed.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &unnamed);
    assert!(ok, "{stdout}\n{stderr}");
    let named = runtime.parent().unwrap().join("named.yaml");
    let (ok, stdout, stderr) =
        generate_with(&fixture(), &runtime, &named, &["--issuer", "primary"]);
    assert!(ok, "{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&unnamed).unwrap(),
        std::fs::read_to_string(&named).unwrap()
    );
}

#[test]
fn an_entry_that_does_not_admit_a_profiles_client_leaves_the_profile_out_of_its_facts() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = two_issuer_runtime(scratch.path());
    let project = project_requiring(runtime.parent().unwrap(), "human");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) =
        generate_with(&project, &runtime, &output, &["--issuer", "partners"]);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(!facts.contains("id: evidence-source"), "{facts}");
    assert!(facts.contains("id: operator"), "{facts}");
}

#[test]
fn an_issuer_on_another_artifact_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    let output = scratch.path().join("openapi");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            OsStr::new("bregctl"),
            OsStr::new("generate"),
            OsStr::new("openapi"),
            fixture().as_os_str(),
            OsStr::new("--output"),
            output.as_os_str(),
            OsStr::new("--issuer"),
            OsStr::new("primary"),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    let report = format!(
        "{}{}",
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap()
    );
    assert!(
        report.contains("--issuer applies to generate identity-facts"),
        "{report}"
    );
    assert!(!output.exists());
    assert!(runtime.exists());
}

/// The runtime with its scope claim renamed to `name`.
fn runtime_with_scope_claim(root: &Path, name: &str) -> PathBuf {
    let runtime = runtime(root);
    edit_runtime(
        &runtime,
        "scopeClaim: scope\n",
        &format!("scopeClaim: {name}\n"),
    );
    runtime
}

#[test]
fn a_renamed_scope_claim_selects_each_profile_by_its_scopes() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime_with_scope_claim(scratch.path(), "registry_scopes");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");
    let facts = read_facts(&output);
    assert_eq!(facts.access_profiles.len(), 3);
    for profile in &facts.access_profiles {
        assert_eq!(
            profile.selected_by,
            std::collections::BTreeMap::from([(
                "registry_scopes".to_owned(),
                profile.scopes.clone()
            )]),
            "{}",
            profile.id
        );
    }
}

#[test]
fn a_scope_claim_the_facts_reader_reserves_is_refused_naming_the_setting() {
    for reserved in ["scp", "roles"] {
        let scratch = tempfile::tempdir().unwrap();
        let runtime = runtime_with_scope_claim(scratch.path(), reserved);
        let output = runtime.parent().unwrap().join("facts.yaml");
        let (ok, stdout, stderr) = generate(&runtime, &output);
        assert!(!ok, "{reserved}: {stdout}\n{stderr}");
        assert!(!output.exists());
        let report = format!("{stdout}{stderr}");
        assert!(
            report.contains("authentication.oidc.issuers.primary.scopeClaim"),
            "{reserved}: {report}"
        );
    }
}

/// An identity deployment that grants `generic-registry-client` the profile
/// `record-reader` and states `scopes` under the renamed scope claim.
fn deployment_stating(scopes: &str) -> String {
    format!(
        "apiVersion: id.registrystack.org/formats/platform/identity-deployment/v1
kind: PlatformIdentityDeployment
organizationUnit:
  handle: registry
  name: Registry
  description: Registry Stack deployment
clients:
  - id: generic-registry-client
    publicJwksFile: keys/client.jwks.json
    grants:
      - product: breg
        accessProfiles: [record-reader]
    claims:
      registry_actor_kind: service
      registry_principal: reader-one
      registry_record_status: open
      registry_scopes: {scopes}
"
    )
}

fn run_generator(
    facts: &Path,
    deployment: &str,
) -> Result<(), registry_thunderid_tooling::ToolingError> {
    let facts_text = std::fs::read_to_string(facts).unwrap();
    let key = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../registry-thunderid-tooling/fixtures/identity/keys/case-portal.jwks.json"),
    )
    .unwrap();
    let jwks = std::collections::BTreeMap::from([("keys/client.jwks.json".to_owned(), key)]);
    let sources = [registry_thunderid_tooling::identity_generate::Source {
        label: "breg",
        bytes: facts_text.as_bytes(),
    }];
    registry_thunderid_tooling::identity_generate::generate(
        &registry_thunderid_tooling::identity_generate::Inputs {
            deployment: registry_thunderid_tooling::identity_generate::Source {
                label: "deployment.yaml",
                bytes: deployment.as_bytes(),
            },
            facts: &sources,
            public_jwks: &jwks,
        },
    )
    .map(|_| ())
}

#[test]
fn the_generator_refuses_a_renamed_scope_claim_that_exceeds_the_grants() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime_with_scope_claim(scratch.path(), "registry_scopes");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate(&runtime, &output);
    assert!(ok, "{stdout}\n{stderr}");

    run_generator(&output, &deployment_stating("[registry:generic:read]"))
        .expect("the granted scope is accepted");
    let refused = run_generator(&output, &deployment_stating("[registry:generic:operate]"))
        .expect_err("a scope the grants do not give is refused");
    let report = refused.report().expect("a report").diagnostics().to_vec();
    assert!(
        report
            .iter()
            .any(|diagnostic| diagnostic.code == "identity.deployment.scope-claim-exceeds-grants"),
        "{report:?}"
    );
}

#[test]
fn a_single_entry_refuses_a_requester_client_it_does_not_admit_without_naming_it() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = runtime(scratch.path());
    edit_runtime(
        &runtime,
        "allowedClients: [generic-registry-client]",
        "allowedClients: [other-client]",
    );
    let project = project_requiring(runtime.parent().unwrap(), "human");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) = generate_for(&project, &runtime, &output);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        report.contains(
            "names a requester client that authentication.oidc.issuers.primary.allowedClients does not admit"
        ),
        "{report}"
    );
    assert!(!report.contains("generic-registry-client"), "{report}");
    assert!(!report.contains("other-client"), "{report}");
}

#[test]
fn a_requester_client_no_entry_admits_is_refused_with_the_runtime_code() {
    let scratch = tempfile::tempdir().unwrap();
    let runtime = two_issuer_runtime(scratch.path());
    edit_runtime(
        &runtime,
        "allowedClients: [generic-registry-client]",
        "allowedClients: [other-client]",
    );
    let project = project_requiring(runtime.parent().unwrap(), "human");
    let output = runtime.parent().unwrap().join("facts.yaml");
    let (ok, stdout, stderr) =
        generate_with(&project, &runtime, &output, &["--issuer", "partners"]);
    assert!(!ok, "{stdout}\n{stderr}");
    assert!(!output.exists());
    let report = format!("{stdout}{stderr}");
    assert!(report.contains("breg.runtime.clients-unlisted"), "{report}");
    assert!(report.contains("authentication.oidc.issuers"), "{report}");
    assert!(!report.contains("generic-registry-client"), "{report}");
}
