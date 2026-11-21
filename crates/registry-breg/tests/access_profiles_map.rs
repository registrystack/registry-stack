// SPDX-License-Identifier: Apache-2.0

//! `accessProfiles` is a mapping from each profile id to the rest of the
//! profile (CFG-ID-5). The key is the id, and profiles are held and written
//! in id order, whatever order the file writes them in.

use registry_breg::contract::{parse_project_yaml, read_module_yaml, read_project_yaml};

const HEAD: &str = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: access-example
  version: '1'
  defaultLanguage: en
  canonicalBaseIri: https://access-example.example.test
datasets:
  - id: test-dataset
recordTypes:
  - id: entry
    primaryDataset: test-dataset
    route: entries
    mutationMode: mutable
    classification: internal
    fields:
      - id: code
        type: string
        maximumLength: 32
        classification: internal
";

fn project(access_profiles: &str) -> String {
    format!("{HEAD}{access_profiles}")
}

const TWO_PROFILES: &str = "accessProfiles:
  zeta:
    principalClaim: registry_principal
    requiredScopes: [entry:read]
    permissions:
      records:
        - recordType: entry
          operations: [get]
          rowBoundaries: unrestricted
  alpha:
    principalClaim: registry_principal
    requiredScopes: unrestricted
";

fn refusals(failure: &registry_breg::CompileFailure) -> Vec<(&str, &str)> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

#[test]
fn a_mapping_of_profiles_reads_each_key_as_the_profile_id_in_id_order() {
    let project = parse_project_yaml(project(TWO_PROFILES).as_bytes()).expect("the mapping reads");
    let ids = project
        .access_profiles
        .iter()
        .map(|profile| profile.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["alpha", "zeta"]);
}

#[test]
fn a_repeated_profile_key_is_refused_as_a_duplicate_key() {
    let written = project(
        "accessProfiles:
  reader:
    principalClaim: registry_principal
    requiredScopes: unrestricted
  reader:
    principalClaim: other_claim
    requiredScopes: unrestricted
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("a repeated key is refused");
    assert_eq!(
        refusals(&failure),
        vec![("yaml.duplicate-key", "project.accessProfiles.reader")],
        "{failure:?}"
    );
}

#[test]
fn the_list_shape_is_refused_with_the_mapping_named() {
    let written = project(
        "accessProfiles:
  - id: reader
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("the list is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.accessProfiles[0].id")],
        "{failure:?}"
    );
    let message = &failure.diagnostics()[0].message;
    assert!(
        message.contains("accessProfiles: {PROFILE_ID: {"),
        "the refusal names the mapping shape: {message}"
    );
}

#[test]
fn an_empty_list_is_refused_with_the_mapping_named() {
    let failure = parse_project_yaml(project("accessProfiles: []\n").as_bytes())
        .expect_err("an empty list is refused");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one refusal: {failure:?}");
    };
    assert_eq!(diagnostic.path, "project.accessProfiles", "{failure:?}");
    assert!(
        diagnostic
            .message
            .contains("a mapping keyed by each item's id"),
        "the refusal names the mapping shape: {}",
        diagnostic.message
    );
}

#[test]
fn a_refusal_inside_a_profile_is_located_at_the_profile_key_line() {
    let written = project(
        "accessProfiles:
  Reader_One:
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
    );
    let report = read_project_yaml("registry.yaml", written.as_bytes()).expect_err("refused");
    let key_line = written
        .lines()
        .position(|line| line.starts_with("  Reader_One:"))
        .expect("the key is written")
        + 1;
    let source = report.diagnostics()[0].source.as_ref().expect("a source");
    assert_eq!(source.line, Some(key_line), "{report:?}");
}

#[test]
fn a_repeated_profile_key_is_located_at_the_repeating_key_line() {
    let written = project(
        "accessProfiles:
  reader:
    principalClaim: registry_principal
    requiredScopes: unrestricted
  reader:
    principalClaim: other_claim
    requiredScopes: unrestricted
",
    );
    let report = read_project_yaml("registry.yaml", written.as_bytes()).expect_err("refused");
    let repeat = written
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with("  reader:"))
        .map(|(index, _)| index + 1)
        .last()
        .expect("the key repeats");
    let source = report.diagnostics()[0].source.as_ref().expect("a source");
    assert_eq!(source.line, Some(repeat), "{report:?}");
}

#[test]
fn an_id_member_inside_a_mapped_profile_is_refused() {
    let written = project(
        "accessProfiles:
  reader:
    id: reader
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("an inner id is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.removed-key", "project.accessProfiles.reader.id")],
        "{failure:?}"
    );
}

#[test]
fn a_profile_key_that_is_not_a_local_id_is_refused() {
    let written = project(
        "accessProfiles:
  Reader_One:
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("the key is refused");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one refusal: {failure:?}");
    };
    assert!(
        diagnostic
            .path
            .starts_with("project.accessProfiles.Reader_One"),
        "{failure:?}"
    );
}

#[test]
fn a_refusal_inside_a_profile_names_the_profile_key_in_its_path() {
    let written = project(
        "accessProfiles:
  reader:
    principalClaim: registry_principal
    requiredScopes: unrestricted
    grants: {}
",
    );
    let failure = parse_project_yaml(written.as_bytes()).expect_err("the member is refused");
    assert_eq!(
        refusals(&failure),
        vec![("config.unknown-key", "project.accessProfiles.reader.grants")],
        "{failure:?}"
    );
}

#[test]
fn a_profile_label_repeated_across_profiles_is_reported_at_each_profile_key() {
    let written = project(
        "accessProfiles:
  reader:
    display: {label: Clerk}
    principalClaim: registry_principal
    requiredScopes: unrestricted
  writer:
    display: {label: Clerk}
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
    );
    let decoded = read_project_yaml("registry.yaml", written.as_bytes()).expect("labels warn only");
    let warnings = decoded.document.warnings();
    let paths = warnings
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.access-profile.duplicate-label")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert!(
        !paths.is_empty()
            && paths.iter().all(|path| [
                "/accessProfiles/reader/display/label",
                "/accessProfiles/writer/display/label"
            ]
            .contains(path)),
        "{warnings:?}"
    );
}

#[test]
fn a_project_writes_its_profiles_as_a_mapping_in_id_order() {
    let project = parse_project_yaml(project(TWO_PROFILES).as_bytes()).expect("the mapping reads");
    let written = serde_json::to_string(&project).expect("the project serializes");
    let zeta = written.find("\"zeta\":{").expect("zeta is a key");
    let alpha = written.find("\"alpha\":{").expect("alpha is a key");
    assert!(alpha < zeta, "profiles are written in id order: {written}");
    let value = serde_json::to_value(&project).unwrap();
    assert!(
        value["accessProfiles"]["zeta"].get("id").is_none(),
        "{value}"
    );
    assert_eq!(
        value["accessProfiles"]["alpha"]["principalClaim"],
        "registry_principal"
    );
}

#[test]
fn an_id_member_inside_a_module_profile_is_refused_like_the_project_level() {
    let project_failure = parse_project_yaml(
        project(
            "accessProfiles:
  reader:
    id: reader
    principalClaim: registry_principal
    requiredScopes: unrestricted
",
        )
        .as_bytes(),
    )
    .expect_err("an inner id is refused");
    let expected = project_failure.diagnostics()[0]
        .message
        .split(" (line")
        .next()
        .unwrap();
    for (list, member) in [
        ("recordTypes", "id: entry"),
        ("extendRecordTypes", "recordType: entry"),
    ] {
        let module = format!(
            "apiVersion: id.registrystack.org/formats/breg/module/v1alpha1
kind: BRegModule
id: extension
version: 0.1.0
{list}:
  - {member}
    accessProfiles:
      reader:
        id: reader
        principalClaim: registry_principal
        requiredScopes: unrestricted
"
        );
        let failure =
            read_module_yaml("module.yaml", module.as_bytes()).expect_err("an inner id is refused");
        let [diagnostic] = failure.diagnostics() else {
            panic!("{list}: one refusal: {failure:?}");
        };
        assert_eq!(
            diagnostic.code, "config.removed-key",
            "{list}: {diagnostic:?}"
        );
        assert_eq!(diagnostic.message, expected, "{list}");
        assert!(
            diagnostic
                .suggested_action
                .contains("accessProfiles: {PROFILE_ID: {"),
            "{list}: the refusal names the mapping shape: {}",
            diagnostic.suggested_action
        );
    }
}
