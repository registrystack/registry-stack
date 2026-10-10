// SPDX-License-Identifier: Apache-2.0

//! How an access profile writes its permissions: one mapping whose members
//! `entities`, `actions`, and `datasets` each list permissions of one kind
//! (CFG-SCHEMA-8). A permission written under another group is refused where
//! the member that does not belong is written.

use registry_breg::contract::{
    parse_project_json, parse_project_yaml, read_project_yaml, DatasetOperation, Operation,
    RegistryProject,
};
use registry_breg::{compile_project, CompileProfile};

const PROJECT: &str = "\
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: access-example
  version: \"1\"
  defaultLanguage: en
  canonicalBaseIri: https://access-example.example.test
entities:
  - id: entry
    primaryDataset: test-dataset
    route: entries
    mutationMode: mutable
    classification: internal
    fields:
      - {id: code, type: string, maximumLength: 32, classification: internal}
accessProfiles:
  - id: reader
    principalClaim: registry_principal
    requiredScopes: unrestricted
";

/// The project with `written` as the lines under its one access profile.
fn document(written: &str) -> String {
    format!("{PROJECT}{written}")
}

fn read(written: &str) -> RegistryProject {
    let document = document(written);
    match read_project_yaml("registry.yaml", document.as_bytes()) {
        Ok(decoded) => decoded.value,
        Err(report) => panic!("the project is read:\n{}", report.render_human()),
    }
}

/// One refusal, as the reader reports it.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    code: String,
    path: String,
    line: usize,
    column: usize,
    message: String,
    action: String,
}

/// Every error the reader answers `written` with, in report order.
fn refusals(written: &str) -> Vec<Refusal> {
    let document = document(written);
    let report = read_project_yaml("registry.yaml", document.as_bytes())
        .err()
        .unwrap_or_else(|| panic!("the project is refused:\n{written}"));
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("a reader diagnostic carries its position");
            Refusal {
                code: diagnostic.code.clone(),
                path: diagnostic.path.clone(),
                line: source.line.expect("a line"),
                column: source.column.expect("a column"),
                message: diagnostic.message.clone(),
                action: diagnostic.suggested_action.clone(),
            }
        })
        .collect()
}

/// The one refusal the reader answers `written` with.
fn refusal(written: &str) -> Refusal {
    let mut refusals = refusals(written);
    assert_eq!(refusals.len(), 1, "one refusal: {refusals:#?}");
    refusals.remove(0)
}

/// The one-based line and column at which `needle` first starts in the
/// project carrying `written`.
fn position(written: &str, needle: &str) -> (usize, usize) {
    let document = document(written);
    let offset = document
        .find(needle)
        .unwrap_or_else(|| panic!("{needle} is written"));
    let before = &document[..offset];
    let line = before.matches('\n').count() + 1;
    let column = offset - before.rfind('\n').map_or(0, |newline| newline + 1) + 1;
    (line, column)
}

const GROUPED: &str = "    permissions:
      entities:
        - entity: entry
          operations: [get, list]
          readableFields: [code]
          rowBoundaries: unrestricted
      actions:
        - action: register
          operations: [invoke]
          targets:
            - entity: entry
              rowBoundaries: unrestricted
        - action: retire
          operations: [invoke]
      datasets:
        - dataset: entries-by-code
          operations: [read-live]
";

#[test]
fn a_profile_groups_its_permissions_by_what_each_names() {
    let project = read(GROUPED);
    let permissions = &project.access_profiles[0].permissions;

    let [entity] = permissions.entities.as_slice() else {
        panic!("one entity permission: {permissions:?}");
    };
    assert_eq!(entity.entity, "entry");
    assert!(entity.operations.contains(&Operation::Get));
    assert!(entity.operations.contains(&Operation::List));
    assert!(entity.row_boundaries.is_empty());

    // Each group keeps the order its permissions are written in.
    let actions: Vec<&str> = permissions
        .actions
        .iter()
        .map(|permission| permission.action.as_str())
        .collect();
    assert_eq!(actions, ["register", "retire"]);
    assert_eq!(permissions.actions[0].targets[0].entity, "entry");

    let [dataset] = permissions.datasets.as_slice() else {
        panic!("one dataset permission: {permissions:?}");
    };
    assert_eq!(dataset.dataset.as_str(), "entries-by-code");
    assert!(dataset.operations.contains(&DatasetOperation::ReadLive));
}

#[test]
fn the_groups_may_be_written_in_any_order() {
    let reordered = "    permissions:
      datasets:
        - dataset: entries-by-code
          operations: [read-live]
      actions:
        - action: register
          operations: [invoke]
          targets:
            - entity: entry
              rowBoundaries: unrestricted
        - action: retire
          operations: [invoke]
      entities:
        - entity: entry
          operations: [get, list]
          readableFields: [code]
          rowBoundaries: unrestricted
";
    assert_eq!(read(reordered), read(GROUPED));
}

#[test]
fn a_group_that_is_omitted_or_empty_grants_nothing() {
    let none = read("");
    let permissions = &none.access_profiles[0].permissions;
    assert!(permissions.entities.is_empty());
    assert!(permissions.actions.is_empty());
    assert!(permissions.datasets.is_empty());

    for written in [
        "    permissions: {}\n",
        "    permissions:\n      entities: []\n",
        "    permissions:\n      actions: []\n",
        "    permissions:\n      datasets: []\n",
        "    permissions:\n      entities: []\n      actions: []\n      datasets: []\n",
    ] {
        assert_eq!(read(written), none, "{written}");
    }

    let compiled = compile_project(&none, &[], CompileProfile::Authoring)
        .expect("a profile that grants nothing compiles");
    assert!(compiled.entities()["entry"].access_profiles.is_empty());
}

#[test]
fn a_profile_writes_its_permissions_back_grouped() {
    let project = read(GROUPED);
    let written = serde_json::to_value(&project).expect("the project serializes");
    let permissions = &written["accessProfiles"][0]["permissions"];
    assert_eq!(permissions["entities"][0]["entity"], "entry");
    assert_eq!(permissions["entities"][0]["rowBoundaries"], "unrestricted");
    assert_eq!(permissions["actions"][0]["action"], "register");
    assert_eq!(
        permissions["actions"][1],
        serde_json::json!({"action": "retire", "operations": ["invoke"]}),
        "an action permission writes only its own members"
    );
    assert_eq!(
        permissions["datasets"],
        serde_json::json!([{"dataset": "entries-by-code", "operations": ["read-live"]}])
    );
    let reread = parse_project_json(&serde_json::to_vec(&written).unwrap())
        .expect("the written project is read again");
    assert_eq!(reread, project);

    // A profile that grants nothing writes every group empty.
    let none = serde_json::to_value(read("")).expect("the project serializes");
    assert_eq!(
        none["accessProfiles"][0]["permissions"],
        serde_json::json!({"entities": [], "actions": [], "datasets": []})
    );
}

#[test]
fn one_permissions_list_is_refused_with_the_grouping_named() {
    // Each is paired with where what `permissions` holds starts, counted in
    // columns from a marker on its line: that is where the refusal points.
    let lists = [
        (
            "    permissions:
      - entity: entry
        operations: [get]
        rowBoundaries: unrestricted
      - action: register
        operations: [invoke]
      - dataset: entries-by-code
        operations: [read-live]
",
            ("- entity:", 0),
        ),
        ("    permissions: []\n", ("permissions:", 13)),
        ("    permissions: unrestricted\n", ("permissions:", 13)),
    ];
    for (written, (marker, columns)) in lists {
        let refusal = refusal(written);
        assert_eq!(refusal.code, "config.invalid-value", "{refusal:?}");
        assert_eq!(refusal.path, "/accessProfiles/0/permissions");
        let (line, column) = position(written, marker);
        assert_eq!(
            (refusal.line, refusal.column),
            (line, column + columns),
            "{refusal:?}"
        );
        assert_eq!(
            refusal.message,
            "expected a mapping with entities, actions, and datasets"
        );
        assert_eq!(
            refusal.action,
            "Group the permissions by what each names: write every permission that names an entity under permissions.entities, every one that names an action under permissions.actions, and every one that names a statistical dataset under permissions.datasets. A profile that grants nothing omits permissions."
        );
    }

    // The compiler's own reading of the same file carries the same refusal.
    let failure = parse_project_yaml(document(lists[0].0).as_bytes())
        .expect_err("the list is refused when the project is read");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(diagnostic.path, "project.accessProfiles[0].permissions");
    assert!(
        diagnostic.message.contains("permissions.entities"),
        "{}",
        diagnostic.message
    );
}

/// A member that belongs to another kind of permission is an unknown key
/// where it is written, and the permission still has to name its own subject.
#[test]
fn a_permission_written_under_another_group_is_refused_where_it_is_written() {
    struct Misplaced {
        written: &'static str,
        group: &'static str,
        unknown: &'static [&'static str],
        missing: &'static [&'static str],
    }
    let cases = [
        Misplaced {
            written: "    permissions:
      actions:
        - entity: entry
          operations: [get]
          rowBoundaries: unrestricted
",
            group: "actions",
            unknown: &["entity", "rowBoundaries"],
            missing: &["action"],
        },
        Misplaced {
            written: "    permissions:
      datasets:
        - entity: entry
          operations: [read-live]
          rowBoundaries: unrestricted
",
            group: "datasets",
            unknown: &["entity", "rowBoundaries"],
            missing: &["dataset"],
        },
        Misplaced {
            written: "    permissions:
      entities:
        - action: register
          operations: [invoke]
          targets: []
          rowBoundaries: unrestricted
",
            group: "entities",
            unknown: &["action", "targets"],
            missing: &["entity"],
        },
        Misplaced {
            written: "    permissions:
      datasets:
        - action: register
          operations: [read-live]
          results: [done]
",
            group: "datasets",
            unknown: &["action", "results"],
            missing: &["dataset"],
        },
        Misplaced {
            written: "    permissions:
      entities:
        - dataset: entries-by-code
          operations: [get]
          rowBoundaries: unrestricted
",
            group: "entities",
            unknown: &["dataset"],
            missing: &["entity"],
        },
        Misplaced {
            written: "    permissions:
      actions:
        - dataset: entries-by-code
          operations: [invoke]
",
            group: "actions",
            unknown: &["dataset"],
            missing: &["action"],
        },
    ];
    for case in cases {
        let item = format!("/accessProfiles/0/permissions/{}/0", case.group);
        let refusals = refusals(case.written);
        assert_eq!(
            refusals.len(),
            case.unknown.len() + case.missing.len(),
            "{refusals:#?}"
        );
        for member in case.unknown {
            let refusal = refusals
                .iter()
                .find(|refusal| refusal.path == format!("{item}/{member}"))
                .unwrap_or_else(|| panic!("{member} is refused: {refusals:#?}"));
            assert_eq!(refusal.code, "config.unknown-key", "{refusal:?}");
            assert_eq!(
                (refusal.line, refusal.column),
                position(case.written, &format!("{member}:")),
                "{refusal:?}"
            );
        }
        for member in case.missing {
            let refusal = refusals
                .iter()
                .find(|refusal| refusal.code == "config.missing-key")
                .unwrap_or_else(|| panic!("{member} is asked for: {refusals:#?}"));
            assert_eq!(refusal.path, item, "{refusal:?}");
            assert_eq!(
                refusal.message,
                format!("the required member `{member}` is missing")
            );
            assert_eq!(refusal.action, format!("Add `{member}`."));
        }
    }
}

#[test]
fn an_action_permission_states_no_row_reach() {
    let written = "    permissions:
      actions:
        - action: register
          operations: [invoke]
          rowBoundaries: unrestricted
";
    let refusal = refusal(written);
    assert_eq!(refusal.code, "config.unknown-key", "{refusal:?}");
    assert_eq!(
        refusal.path,
        "/accessProfiles/0/permissions/actions/0/rowBoundaries"
    );
    assert_eq!(
        (refusal.line, refusal.column),
        position(written, "rowBoundaries:")
    );
}

/// Every member only an entity permission carries is refused on an action
/// permission when the project is read.
#[test]
fn an_action_permission_carries_no_entity_member() {
    for (member, value) in [
        ("readableFields", "[code]"),
        ("readableRequestFields", "[status]"),
        ("writableFields", "[code]"),
        ("filterableFields", "[code]"),
        ("sortableFields", "[code]"),
        ("spatialQueries", "{}"),
        ("membershipBoundaries", "[]"),
        ("requireConsent", "[]"),
        ("requestVisibility", "{}"),
        ("lookups", "[]"),
        ("readPaths", "[]"),
        ("applyTargets", "[]"),
        ("submitterTargets", "[]"),
        ("requestPresence", "[]"),
        ("allowCount", "true"),
        ("revisionAccess", "true"),
        ("provenanceFields", "[]"),
        ("allowDataExport", "true"),
    ] {
        let written = format!(
            "    permissions:
      actions:
        - action: register
          operations: [invoke]
          {member}: {value}
"
        );
        let refusal = refusal(&written);
        assert_eq!(refusal.code, "config.unknown-key", "{refusal:?}");
        assert_eq!(
            refusal.path,
            format!("/accessProfiles/0/permissions/actions/0/{member}")
        );
        assert_eq!(
            (refusal.line, refusal.column),
            position(&written, &format!("{member}:"))
        );
    }
}

#[test]
fn an_entity_permission_states_its_row_reach() {
    let written = "    permissions:
      entities:
        - entity: entry
          operations: [get]
";
    let refusal = refusal(written);
    assert_eq!(refusal.code, "config.invalid-value", "{refusal:?}");
    assert_eq!(refusal.path, "/accessProfiles/0/permissions/entities/0");
    assert_eq!(
        (refusal.line, refusal.column),
        position(written, "entity: entry")
    );
    assert_eq!(
        refusal.message,
        "expected an entity permission with rowBoundaries"
    );
    assert_eq!(
        refusal.action,
        "Declare rowBoundaries on the permission: list the row boundaries that bind rows to the caller's claims, or write unrestricted to reach every row."
    );

    let empty = "    permissions:
      entities:
        - entity: entry
          operations: [get]
          rowBoundaries: []
";
    let refusal = self::refusal(empty);
    assert_eq!(refusal.code, "config.invalid-value", "{refusal:?}");
    assert_eq!(
        refusal.path,
        "/accessProfiles/0/permissions/entities/0/rowBoundaries"
    );
    assert!(
        refusal
            .action
            .contains("write unrestricted to reach every row"),
        "{refusal:?}"
    );
}

#[test]
fn a_group_lists_only_its_own_operations() {
    for (group, subject, operation, rest) in [
        (
            "entities",
            "entity: entry",
            "read-live",
            "\n          rowBoundaries: unrestricted",
        ),
        (
            "entities",
            "entity: entry",
            "publish",
            "\n          rowBoundaries: unrestricted",
        ),
        (
            "entities",
            "entity: entry",
            "read-releases",
            "\n          rowBoundaries: unrestricted",
        ),
        ("actions", "action: register", "read-live", ""),
        ("actions", "action: register", "publish", ""),
        ("actions", "action: register", "read-releases", ""),
        ("datasets", "dataset: entries-by-code", "get", ""),
        ("datasets", "dataset: entries-by-code", "invoke", ""),
    ] {
        let written = format!(
            "    permissions:
      {group}:
        - {subject}
          operations: [{operation}]{rest}
"
        );
        let refusal = refusal(&written);
        assert_eq!(refusal.code, "config.unknown-variant", "{refusal:?}");
        assert_eq!(
            refusal.path,
            format!("/accessProfiles/0/permissions/{group}/0/operations/0")
        );
        assert_eq!(
            (refusal.line, refusal.column),
            position(&written, &format!("{operation}]"))
        );
    }
}

#[test]
fn a_dataset_permission_lists_at_least_one_operation() {
    let written = "    permissions:
      datasets:
        - dataset: entries-by-code
          operations: []
";
    let refusal = refusal(written);
    assert_eq!(refusal.code, "config.invalid-value", "{refusal:?}");
    assert_eq!(
        refusal.path,
        "/accessProfiles/0/permissions/datasets/0/operations"
    );
    assert_eq!((refusal.line, refusal.column), position(written, "[]"));
    assert_eq!(
        refusal.message,
        "expected at least one of read-live, publish, or read-releases"
    );
}

#[test]
fn a_permission_lists_each_operation_once() {
    for (group, subject, operation, rest) in [
        (
            "entities",
            "entity: entry",
            "get",
            "\n          rowBoundaries: unrestricted",
        ),
        ("actions", "action: register", "invoke", ""),
        ("datasets", "dataset: entries-by-code", "read-live", ""),
    ] {
        let written = format!(
            "    permissions:
      {group}:
        - {subject}
          operations: [{operation}, {operation}]{rest}
"
        );
        let refusal = refusal(&written);
        assert_eq!(refusal.code, "config.duplicate-item", "{refusal:?}");
        assert_eq!(
            refusal.path,
            format!("/accessProfiles/0/permissions/{group}/0/operations/1")
        );
    }
}

#[test]
fn permissions_holds_only_the_three_groups() {
    let written = "    permissions:
      entity:
        - entity: entry
          operations: [get]
          rowBoundaries: unrestricted
";
    let refusal = refusal(written);
    assert_eq!(refusal.code, "config.unknown-key", "{refusal:?}");
    assert_eq!(refusal.path, "/accessProfiles/0/permissions/entity");
    assert_eq!((refusal.line, refusal.column), position(written, "entity:"));
    assert!(
        refusal.action.contains("entities"),
        "the closest accepted key is offered: {refusal:?}"
    );
}
