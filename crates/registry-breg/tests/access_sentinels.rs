// SPDX-License-Identifier: Apache-2.0

//! How an authored project writes "no restriction": the keyword
//! `unrestricted` on a member that grants reach, and omission on a member
//! that only narrows. An empty list is refused in both places, because it
//! reads as both "none" and "any" (CFG-EMPTY-2).

use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::{
    compile_project, parse_project_json, CompileFailure, CompileProfile, CompiledRegistry,
};
use serde_json::{json, Value};

fn boundary() -> Value {
    json!({"field":"district","claim":"districts","operator":"in"})
}

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"access-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access-example.example.test"},
        "entities":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"},
                    {"id":"district","type":"string","maxLength":32,"classification":"internal"}]}],
        "accessProfiles":[{"id":"reader","principalClaim":"registry_principal","requiredScopes":["entry:read"],
          "permissions":[{"entity":"entry","operations":["get","list"],
            "readableFields":["code","district"],"filterableFields":["district"],
            "rowBoundaries":[boundary()]}]}]
    })
}

/// A project carrying every authored place a row reach is written. It is
/// read, never compiled.
fn every_row_reach() -> Value {
    let mut value = source();
    value["accessProfiles"][0]["permissions"] = json!([
        {"entity":"entry","operations":["get"],"readableFields":["code"],
         "rowBoundaries":[boundary()],
         "applyTargets":[{"entity":"entry","rowBoundaries":[boundary()]}],
         "requestPresence":[{"requestType":"entry-change","rowBoundaries":[boundary()]}]},
        {"action":"register","operations":["invoke"],
         "targets":[{"entity":"entry","rowBoundaries":[boundary()]}]}
    ]);
    value
}

const ROW_REACH_SITES: [(&str, &str); 4] = [
    (
        "/accessProfiles/0/permissions/0/rowBoundaries",
        "project.accessProfiles[0].permissions[0].rowBoundaries",
    ),
    (
        "/accessProfiles/0/permissions/0/applyTargets/0/rowBoundaries",
        "project.accessProfiles[0].permissions[0].applyTargets[0].rowBoundaries",
    ),
    (
        "/accessProfiles/0/permissions/0/requestPresence/0/rowBoundaries",
        "project.accessProfiles[0].permissions[0].requestPresence[0].rowBoundaries",
    ),
    (
        "/accessProfiles/0/permissions/1/targets/0/rowBoundaries",
        "project.accessProfiles[0].permissions[1].targets[0].rowBoundaries",
    ),
];

fn read(value: &Value) -> Result<registry_breg::contract::RegistryProject, CompileFailure> {
    parse_project_yaml(&serde_json::to_vec(value).unwrap())
}

fn compile(value: &Value) -> Result<CompiledRegistry, CompileFailure> {
    compile_project(&read(value)?, &[], CompileProfile::Authoring)
}

/// The one refusal a read answers with, as its code, path, and message.
fn refusal(value: &Value) -> (String, String, String) {
    let failure = read(value).expect_err("the project is refused when it is read");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the project: {failure:?}");
    };
    (
        diagnostic.code.clone(),
        diagnostic.path.clone(),
        diagnostic.message.clone(),
    )
}

fn set(value: &mut Value, pointer: &str, written: Value) {
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("{pointer} exists")) = written;
}

fn remove(value: &mut Value, parent: &str, member: &str) {
    value
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("{parent} is a mapping"))
        .remove(member)
        .unwrap_or_else(|| panic!("{parent} has {member}"));
}

#[test]
fn required_scopes_is_written_as_unrestricted_or_as_a_list_of_at_least_one_scope() {
    let mut omitted = source();
    remove(&mut omitted, "/accessProfiles/0", "requiredScopes");
    let (code, path, message) = refusal(&omitted);
    assert_eq!(code, "config.missing-key", "{message}");
    assert!(path.starts_with("project.accessProfiles[0]"), "{path}");

    for written in [json!([]), json!("everything")] {
        let mut value = source();
        set(&mut value, "/accessProfiles/0/requiredScopes", written);
        let (code, path, message) = refusal(&value);
        assert_eq!(code, "config.invalid-value", "{message}");
        assert_eq!(path, "project.accessProfiles[0].requiredScopes");
        assert!(
            message.contains("write unrestricted to require none"),
            "the refusal names the sentinel: {message}"
        );
    }

    let mut value = source();
    set(
        &mut value,
        "/accessProfiles/0/requiredScopes",
        json!("unrestricted"),
    );
    let project = read(&value).expect("unrestricted is accepted");
    assert!(project.access_profiles[0].required_scopes.is_empty());
    let compiled = compile(&value).expect("the project compiles");
    assert!(compiled.entities()["entry"].access_profiles["reader"]
        .required_scopes
        .is_empty());

    let listed = read(&source()).expect("a list of scopes is accepted");
    assert!(listed.access_profiles[0]
        .required_scopes
        .contains("entry:read"));
}

#[test]
fn a_member_that_only_narrows_a_profile_is_omitted_not_written_empty() {
    for member in ["requiredPurposes", "requesterClients"] {
        for written in [json!([]), json!("unrestricted")] {
            let mut value = source();
            value["accessProfiles"][0][member] = written;
            let (code, path, message) = refusal(&value);
            assert_eq!(code, "config.invalid-value", "{message}");
            assert_eq!(path, format!("project.accessProfiles[0].{member}"));
            assert!(
                message.contains(&format!("Omit {member}")),
                "the refusal names the fix: {message}"
            );
        }
        let project = read(&source()).expect("an omitted member is accepted");
        assert!(project.access_profiles[0].required_purposes.is_empty());
        assert!(project.access_profiles[0].requester_clients.is_empty());
    }
}

#[test]
fn row_reach_is_written_as_unrestricted_or_as_a_list_of_at_least_one_boundary() {
    read(&every_row_reach()).expect("a list of boundaries is accepted at every site");
    for (pointer, path) in ROW_REACH_SITES {
        let mut empty = every_row_reach();
        set(&mut empty, pointer, json!([]));
        let (code, refused_at, message) = refusal(&empty);
        assert_eq!(code, "config.invalid-value", "{message}");
        assert_eq!(refused_at, path);
        assert!(
            message.contains("write unrestricted to reach every row"),
            "the refusal names the sentinel: {message}"
        );

        let mut open = every_row_reach();
        set(&mut open, pointer, json!("unrestricted"));
        read(&open).unwrap_or_else(|failure| panic!("{pointer} takes unrestricted: {failure:?}"));
    }

    let mut open = every_row_reach();
    for (pointer, _) in ROW_REACH_SITES {
        set(&mut open, pointer, json!("unrestricted"));
    }
    let project = read(&open).expect("unrestricted is accepted at every site");
    let [entity, action] = project.access_profiles[0].permissions.as_slice() else {
        panic!("the profile holds two permissions");
    };
    assert!(entity.row_boundaries.is_empty());
    assert!(entity.apply_targets[0].row_boundaries.is_empty());
    assert!(entity.request_presence[0].row_boundaries.is_empty());
    assert!(action.targets[0].row_boundaries.is_empty());
}

#[test]
fn an_entity_permission_that_omits_its_row_reach_is_refused_with_the_sentinel_named() {
    let mut value = source();
    remove(
        &mut value,
        "/accessProfiles/0/permissions/0",
        "rowBoundaries",
    );
    let (code, path, message) = refusal(&value);
    assert_eq!(code, "config.invalid-value", "{message}");
    assert_eq!(path, "project.accessProfiles[0].permissions[0]");
    assert!(
        message.contains("write unrestricted to reach every row"),
        "the refusal names the sentinel: {message}"
    );
}

#[test]
fn an_access_requirement_only_narrows_so_it_takes_no_empty_list_and_no_unrestricted() {
    for member in ["requiredScopes", "allowedPurposes", "rowBoundaries"] {
        for written in [json!([]), json!("unrestricted")] {
            let mut value = source();
            value["entities"][0]["accessRequirements"] = json!({
                "requiredScopes":["entry:read"],
                "allowedPurposes":["administration"],
                "rowBoundaries":[boundary()],
            });
            value["entities"][0]["accessRequirements"][member] = written;
            let (code, path, message) = refusal(&value);
            assert_eq!(code, "config.invalid-value", "{message}");
            assert_eq!(
                path,
                format!("project.entities[0].accessRequirements.{member}")
            );
            assert!(
                message.contains(&format!("Omit {member}")) && message.contains("only narrows"),
                "the refusal names the fix and its reason: {message}"
            );
        }
    }

    let module = json!({"id":"extra","version":"1","extendEntities":[{
        "entity":"entry","accessRequirements":{"requiredScopes":[]}
    }]});
    let failure = parse_module_yaml(&serde_json::to_vec(&module).unwrap())
        .expect_err("a module requirement written empty is refused");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the module: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(
        diagnostic.path,
        "module.extendEntities[0].accessRequirements.requiredScopes"
    );
}

#[test]
fn an_authored_project_serializes_to_the_form_it_is_read_from() {
    let mut value = every_row_reach();
    set(
        &mut value,
        "/accessProfiles/0/requiredScopes",
        json!("unrestricted"),
    );
    for (pointer, _) in ROW_REACH_SITES {
        set(&mut value, pointer, json!("unrestricted"));
    }
    value["entities"][0]["accessRequirements"] = json!({"allowedPurposes":["administration"]});
    let project = read(&value).expect("the project is read");

    let written = serde_json::to_value(&project).expect("the project serializes");
    let profile = &written["accessProfiles"][0];
    assert_eq!(profile["requiredScopes"], "unrestricted");
    assert!(profile.get("requiredPurposes").is_none(), "{profile}");
    assert!(profile.get("requesterClients").is_none(), "{profile}");
    for (pointer, _) in ROW_REACH_SITES {
        assert_eq!(written.pointer(pointer), Some(&json!("unrestricted")));
    }
    assert_eq!(
        written["entities"][0]["accessRequirements"],
        json!({"allowedPurposes":["administration"]})
    );

    let read_back = parse_project_json(&serde_json::to_vec(&written).unwrap())
        .expect("the serialized project is read back");
    assert_eq!(read_back, project);
}

fn finding_paths(compiled: &CompiledRegistry, code: &str) -> Vec<String> {
    compiled
        .findings()
        .iter()
        .filter(|finding| finding.code == code)
        .map(|finding| finding.path.clone())
        .collect()
}

/// `source()` with a second profile, `open`, that requires no scope.
fn beside_an_open_profile() -> Value {
    let mut value = source();
    let mut open = value["accessProfiles"][0].clone();
    open["id"] = json!("open");
    open["requiredScopes"] = json!("unrestricted");
    value["accessProfiles"].as_array_mut().unwrap().push(open);
    value
}

#[test]
fn an_unrestricted_profile_beside_a_narrower_one_is_reported_without_changing_authority() {
    const CODE: &str = "breg.access.profile-subsumes-narrower";
    let compiled = compile(&beside_an_open_profile()).expect("the project compiles");
    assert_eq!(
        finding_paths(&compiled, CODE),
        vec!["project.accessProfiles[id=open].requiredScopes"]
    );
    let finding = compiled
        .findings()
        .iter()
        .find(|finding| finding.code == CODE)
        .unwrap();
    assert!(
        finding.message.contains("`reader`"),
        "the finding names the narrower profile: {}",
        finding.message
    );
    assert!(compiled.entities()["entry"].access_profiles["open"]
        .required_scopes
        .is_empty());
    assert!(compiled.entities()["entry"].access_profiles["reader"]
        .required_scopes
        .contains("entry:read"));

    // A profile that requires no scope alone opens no door another profile
    // closed.
    let mut alone = source();
    set(
        &mut alone,
        "/accessProfiles/0/requiredScopes",
        json!("unrestricted"),
    );
    assert!(finding_paths(&compile(&alone).unwrap(), CODE).is_empty());

    // Two profiles that require no scope behind the same gates admit each
    // other's tokens, so a caller of either reaches what both grant.
    let mut both = beside_an_open_profile();
    set(
        &mut both,
        "/accessProfiles/0/requiredScopes",
        json!("unrestricted"),
    );
    let compiled = compile(&both).unwrap();
    assert_eq!(
        finding_paths(&compiled, CODE),
        vec![
            "project.accessProfiles[id=open].requiredScopes",
            "project.accessProfiles[id=reader].requiredScopes"
        ]
    );
    for (finding, other) in compiled
        .findings()
        .iter()
        .filter(|finding| finding.code == CODE)
        .zip(["`reader`", "`open`"])
    {
        assert!(
            finding.message.contains(other) && finding.message.matches('`').count() == 2,
            "each finding names the other profile and never itself: {}",
            finding.message
        );
    }

    // Each gate the open profile adds that the narrower one does not meet
    // keeps the narrower profile's tokens out of it.
    for (gate, members) in [
        (
            "a client binding",
            json!({"actorKind":"service","requesterClients":["open-client"]}),
        ),
        ("a purpose", json!({"requiredPurposes":["audit"]})),
        (
            "a principal claim",
            json!({"principalClaim":"other_principal"}),
        ),
    ] {
        let mut value = beside_an_open_profile();
        for (member, written) in members.as_object().unwrap() {
            value["accessProfiles"][1][member] = written.clone();
        }
        assert!(
            finding_paths(&compile(&value).unwrap(), CODE).is_empty(),
            "{gate} on the open profile separates the two"
        );
    }

    // The same gate on both profiles separates nothing.
    let mut shared = beside_an_open_profile();
    for index in [0, 1] {
        shared["accessProfiles"][index]["actorKind"] = json!("service");
        shared["accessProfiles"][index]["requesterClients"] = json!(["portal"]);
        shared["accessProfiles"][index]["requiredPurposes"] = json!(["administration"]);
    }
    assert_eq!(
        finding_paths(&compile(&shared).unwrap(), CODE),
        vec!["project.accessProfiles[id=open].requiredScopes"]
    );

    // A service profile's tokens are admitted by a profile that names no
    // actor kind. A different kind on each profile admits no common token.
    let mut kinds = beside_an_open_profile();
    kinds["accessProfiles"][0]["actorKind"] = json!("service");
    kinds["accessProfiles"][0]["requesterClients"] = json!(["portal"]);
    assert_eq!(
        finding_paths(&compile(&kinds).unwrap(), CODE),
        vec!["project.accessProfiles[id=open].requiredScopes"]
    );
    kinds["accessProfiles"][1]["actorKind"] = json!("human");
    kinds["accessProfiles"][1]["requesterClients"] = json!(["portal"]);
    assert!(finding_paths(&compile(&kinds).unwrap(), CODE).is_empty());
}

#[test]
fn writing_the_decision_replaces_the_no_required_scope_findings() {
    let compiled = compile(&beside_an_open_profile()).expect("the project compiles");
    assert!(
        compiled
            .findings()
            .iter()
            .all(|finding| !finding.code.ends_with("no-required-scope")),
        "{:?}",
        compiled.findings()
    );
}

#[test]
fn an_item_spelled_like_a_wildcard_is_reported_as_one_name() {
    const CODE: &str = "breg.access.wildcard-spelled-item";
    assert!(finding_paths(&compile(&source()).unwrap(), CODE).is_empty());

    let mut value = source();
    value["accessProfiles"][0]["requiredScopes"] = json!(["*"]);
    value["accessProfiles"][0]["requiredPurposes"] = json!(["unrestricted"]);
    value["accessProfiles"][0]["actorKind"] = json!("service");
    value["accessProfiles"][0]["requesterClients"] = json!(["*", "portal"]);
    value["entities"][0]["accessRequirements"] =
        json!({"requiredScopes":["*"],"allowedPurposes":["unrestricted"]});
    let compiled = compile(&value).expect("a wildcard spelling is a name, so the project compiles");
    assert_eq!(
        finding_paths(&compiled, CODE),
        vec![
            "entities[id=entry].accessRequirements.allowedPurposes",
            "entities[id=entry].accessRequirements.requiredScopes",
            "project.accessProfiles[id=reader].requesterClients",
            "project.accessProfiles[id=reader].requiredPurposes",
            "project.accessProfiles[id=reader].requiredScopes",
        ]
    );
    assert!(compiled.entities()["entry"].access_profiles["reader"]
        .required_scopes
        .contains("*"));
}
