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
        assert!(!registry
            .findings()
            .iter()
            .any(|finding| finding.code == "access.profile.unrestricted_collection"));
    }
}

#[test]
fn membership_boundaries_refuse_unenforced_authority_paths() {
    for (path, value, code) in [
        (
            "/accessProfiles/0/grants/0/operations",
            json!(["get", "patch"]),
            "access.membership.read_only",
        ),
        (
            "/accessProfiles/0/grants/0/reviewStages",
            json!([{"stage":"review"}]),
            "access.membership.read_only",
        ),
        (
            "/accessProfiles/0/grants/0/applyTargets",
            json!([{"entity":"facility","rowBoundaries":[]}]),
            "access.membership.read_only",
        ),
        (
            "/accessProfiles/0/grants/0/requestPresence",
            json!([{"requestType":"request","rowBoundaries":[]}]),
            "access.membership.read_only",
        ),
        (
            "/accessProfiles/0/anonymous",
            json!(true),
            "access.membership.authentication",
        ),
        (
            "/accessProfiles/0/requiredScopes",
            json!(["records:read"]),
            "access.requirements.scope_missing",
        ),
        (
            "/accessProfiles/0/grants/0/membershipBoundaries/0/field",
            json!("label"),
            "access.membership.key_type",
        ),
        (
            "/accessProfiles/0/grants/0/membershipBoundaries/0/principalField",
            json!("active"),
            "access.membership.principal_type",
        ),
        (
            "/accessProfiles/0/grants/0/membershipBoundaries/0/activeField",
            json!("principal"),
            "access.membership.active_type",
        ),
        (
            "/accessProfiles/0/grants/0/membershipBoundaries/0/membershipEntity",
            json!("facility"),
            "access.membership.source_recursive",
        ),
        (
            "/entities/1/accessRequirements",
            json!({"rowBoundaries":[{"field":"principal","claim":"principal","operator":"equals"}]}),
            "access.membership.source_row_requirement",
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
    value["entities"][0]["readPaths"] =
        json!([{"id":"facilities","through":"membership","to":"facility","route":"facilities"}]);
    value["accessProfiles"][1]["grants"][0]["readPaths"] =
        json!([{"path":"facilities","readableFields":["label"]}]);
    let failure =
        compile(&value).expect_err("read paths cannot ignore protected target membership");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access.membership.read_path_target"));

    let mut action = action_requirements::project();
    action["accessProfiles"][0]["grants"][0]["membershipBoundaries"] =
        source("facility")["accessProfiles"][0]["grants"][0]["membershipBoundaries"].clone();
    let failure = compile(&action)
        .expect_err("an action grant must not silently ignore entity membership rules");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.grant.entity_fields_forbidden"));
}
