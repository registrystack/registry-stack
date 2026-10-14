// SPDX-License-Identifier: Apache-2.0

#[path = "support/action_requirements.rs"]
mod action_requirements;
#[path = "support/membership_fixture.rs"]
mod membership_fixture;

use membership_fixture::{compile, source};
use serde_json::json;

#[test]
fn membership_boundaries_compile_for_distinct_registry_models() {
    for root in ["facility", "document"] {
        let registry = compile(&source(root))
            .expect("same membership primitive compiles for distinct registries");
        let profile = &registry.entities()[root].access_profiles["member"];
        assert_eq!(profile.membership_boundaries.len(), 1);
        assert_eq!(
            registry.entities()[root].membership_boundaries["member"].len(),
            1
        );
        let sql = registry
            .ddl()
            .statements
            .iter()
            .map(|statement| statement.sql.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(sql.contains(
            "LANGUAGE plpgsql STABLE STRICT SECURITY INVOKER SET search_path = pg_catalog"
        ));
        assert!(!sql.contains("SECURITY DEFINER"));
        assert!(sql.contains("FORCE ROW LEVEL SECURITY"));
        let explained =
            serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
        assert!(explained.to_string().contains("membershipBoundaries"));
        assert!(explained.to_string().contains("membershipRecordType"));
        assert!(!explained.to_string().contains("membershipEntity"));
        let compiled =
            serde_json::to_value(&registry.entities()[root].membership_boundaries["member"][0])
                .unwrap();
        assert_eq!(compiled["membershipRecordType"], "membership");
        assert!(compiled.get("membershipEntity").is_none());
        assert!(!registry
            .findings()
            .iter()
            .any(|finding| finding.code == "breg.access.profile-unrestricted-collection"));
    }
}

#[test]
fn membership_reference_uses_one_positioned_spelling() {
    let source = source("facility");
    let bytes = serde_json::to_vec(&source).unwrap();
    let decoded = registry_breg::contract::read_project_yaml("registry.yaml", &bytes).unwrap();
    let wire = serde_json::to_value(&decoded.value).unwrap();
    assert_eq!(
        wire.pointer(
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/membershipRecordType"
        ),
        Some(&json!("membership"))
    );
    for value in [json!("membership"), json!(""), serde_json::Value::Null] {
        let mut previous = source.clone();
        let boundary = previous
            .pointer_mut("/accessProfiles/0/permissions/records/0/membershipBoundaries/0")
            .unwrap()
            .as_object_mut()
            .unwrap();
        boundary.remove("membershipRecordType");
        boundary.insert("membershipEntity".to_owned(), value);
        let report = registry_breg::contract::read_project_yaml(
            "registry.yaml",
            &serde_json::to_vec_pretty(&previous).unwrap(),
        )
        .expect_err("previous reference is refused");
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .expect("migration guidance is present");
        assert_eq!(
            diagnostic.path,
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/membershipEntity"
        );
        assert!(diagnostic.suggested_action.contains("membershipRecordType"));
        assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    }
}

#[test]
fn membership_boundaries_refuse_unenforced_authority_paths() {
    for (path, value, code) in [
        (
            "/accessProfiles/0/permissions/records/0/operations",
            json!(["get", "patch"]),
            "breg.access.membership-read-only",
        ),
        (
            "/accessProfiles/0/requiredScopes",
            json!(["records:read"]),
            "breg.access.requirements-scope-missing",
        ),
        (
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/field",
            json!("label"),
            "breg.access.membership-key-type",
        ),
        (
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/principalField",
            json!("active"),
            "breg.access.membership-principal-type",
        ),
        (
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/activeField",
            json!("principal"),
            "breg.access.membership-active-type",
        ),
        (
            "/accessProfiles/0/permissions/records/0/membershipBoundaries/0/membershipRecordType",
            json!("facility"),
            "breg.access.membership-source-recursive",
        ),
        (
            "/recordTypes/1/accessRequirements",
            json!({"rowBoundaries":[{"field":"principal","claim":"principal","operator":"equals"}]}),
            "breg.access.membership-source-row-requirement",
        ),
    ] {
        let mut value_source = source("facility");
        // Some optional fields are absent from the baseline document.
        let (parent, name) = path.rsplit_once('/').unwrap();
        value_source.pointer_mut(parent).unwrap()[name] = value;
        let failure = compile(&value_source)
            .expect_err("unsupported membership authority must fail at compilation");
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "wanted {code}: {failure:?}"
        );
    }
    let mut value = source("facility");
    value["recordTypes"][0]["readPaths"] =
        json!([{"id":"facilities","through":"membership","to":"facility","route":"facilities"}]);
    value["accessProfiles"][1]["permissions"]["records"][0]["readPaths"] =
        json!([{"path":"facilities","readableFields":["label"]}]);
    let failure =
        compile(&value).expect_err("read paths cannot ignore protected target membership");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access.membership-read-path-target"));

    let mut action = action_requirements::project();
    action["accessProfiles"][0]["permissions"]["actions"][0]["membershipBoundaries"] =
        source("facility")["accessProfiles"][0]["permissions"]["records"][0]
            ["membershipBoundaries"]
            .clone();
    let failure = registry_breg::parse_project_yaml(&serde_json::to_vec(&action).unwrap())
        .expect_err("an action grant must not silently ignore entity membership rules");
    let refusals: Vec<_> = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect();
    assert_eq!(
        refusals,
        [(
            "config.unknown-key",
            "project.accessProfiles[0].permissions.actions[0].membershipBoundaries"
        )]
    );
}
