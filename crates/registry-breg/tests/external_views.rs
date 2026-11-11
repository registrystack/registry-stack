// SPDX-License-Identifier: Apache-2.0

use registry_breg::contract::parse_project_yaml;
use registry_breg::{compile_project, CompileProfile};

const PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: linked-example
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://registry.example.test
datasets: [{id: local-records}]
recordTypes:
  - id: local-record
    primaryDataset: local-records
    route: local-records
    mutationMode: mutable
    classification: internal
    fields:
      - {id: subject-key, type: string, maximumLength: 32, classification: internal}
      - {id: local-title, type: string, maximumLength: 120, classification: internal}
externalRecordTypes:
  - id: external-subject
    authority: urn:example:source
    identifierScheme: urn:example:subject-key
    fields:
      - {id: label, type: string, classification: internal}
      - {id: code, type: integer, classification: restricted}
externalProjections:
  - id: approved-subjects
    recordType: external-subject
    operation: subjects-by-key
    operationVersion: "1"
    purpose: local-consultation
    scope: approved-subjects
    selectorScheme: urn:example:subject-key
    mode: indexed
    cardinality: one
    cacheTtlSeconds: 600
    fields: [label, code]
externalViews:
  - id: local-with-subject
    recordType: local-record
    links:
      - id: subject
        projection: approved-subjects
        fromField: subject-key
        identifierScheme: urn:example:subject-key
        fields: [label, code]
accessProfiles:
  - id: reader
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [local-consultation]
    permissions:
      records:
        - recordType: local-record
          operations: [get, list]
          readableFields: [local-title]
          rowBoundaries: unrestricted
      externalViews:
        - view: local-with-subject
          links:
            - link: subject
              readableFields: [label]
              filterableFields: [label]
"#;

fn compile(source: &str) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    let project = parse_project_yaml(source.as_bytes()).expect("external views parse");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn rejects(source: &str, expected: &str) {
    let refusal = compile(source).expect_err("invalid external authoring is refused");
    assert!(
        refusal.diagnostics().iter().any(|d| d.code == expected),
        "expected {expected}: {refusal:?}"
    );
}

#[test]
fn external_views_are_compiled_separately_from_owned_fields_and_permissions() {
    let registry = compile(PROJECT).expect("an explicitly granted external view compiles");
    let external = registry.external_views();
    let view = &external.views["local-with-subject"];
    let grant = &external.grants["reader"]["local-with-subject"].links[0];
    assert_eq!(view.links[0].from_field.as_str(), "subject-key");
    assert_eq!(
        grant
            .readable_fields
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>(),
        ["label"]
    );
    assert!(!registry.entities()["local-record"]
        .fields
        .contains_key("label"));
    assert!(registry
        .artifacts()
        .get("compiled/external-views.json")
        .is_some());
}

#[test]
fn direct_link_rejects_another_identifier_scheme() {
    let original = "        identifierScheme: urn:example:subject-key";
    let changed = "        identifierScheme: urn:example:other-key";
    rejects(
        &PROJECT.replace(original, changed),
        "breg.external-view.identifier-scheme-mismatch",
    );
}

#[test]
fn query_grant_cannot_use_a_hidden_external_field() {
    rejects(
        &PROJECT.replace("filterableFields: [label]", "filterableFields: [code]"),
        "breg.external-view.processing-wider-than-read",
    );
}

#[test]
fn live_projection_cannot_have_a_cache_or_query_grant() {
    let live = PROJECT.replace("mode: indexed", "mode: live");
    rejects(&live, "breg.external-view.live-cache");
    rejects(
        &live.replace("    cacheTtlSeconds: 600\n", ""),
        "breg.external-view.live-query",
    );
}

#[test]
fn refresh_requires_a_separate_scoped_service_profile() {
    let source = PROJECT.replace(
        "    permissions:\n      records:",
        "    permissions:\n      refreshExternalProjections: [approved-subjects]\n      records:",
    );
    rejects(&source, "breg.external-view.refresh-service-profile");
}

#[test]
fn external_view_cannot_bypass_a_local_record_permission() {
    let source = PROJECT.replace("operations: [get, list]", "operations: [list]");
    rejects(&source, "breg.external-view.root-read-missing");
}

#[test]
fn external_openapi_uses_named_view_and_field_grants() {
    let registry = compile(PROJECT).expect("authorised view fixture compiles");
    let document: serde_json::Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let operation =
        &document["paths"]["/v1/external-views/local-with-subject/subject/records"]["get"];
    let schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    let fields = &schema["properties"]["records"]["items"]["properties"]["fields"]["properties"];
    assert_eq!(fields["label"]["type"], "string");
    assert!(fields.get("code").is_none());
    assert!(schema["properties"].get("count").is_none());
    assert!(document["paths"]["/v1/external-views/local-with-subject/subject/refresh"].is_null());
    assert!(document["paths"]["/v1/external-refresh-plans/{plan}/step"].is_null());
}

#[test]
fn the_field_a_view_links_from_is_marked_on_its_root_entity() {
    let registry = compile(PROJECT).expect("an explicitly granted external view compiles");
    let entity = &registry.entities()["local-record"];
    assert_eq!(
        entity
            .external_link_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["subject-key"],
        "only the linked field carries the link-key rule"
    );
}

#[test]
fn refresh_link_gets_a_managed_index_matching_its_row_policy() {
    let source = format!(
        "{PROJECT}\n{}",
        r#"  - id: refresh
    principalClaim: registry_principal
    actorKind: service
    requesterClients: [refresh-worker]
    requiredScopes: [registry.refresh]
    requiredPurposes: [local-consultation]
    permissions:
      records:
        - recordType: local-record
          operations: [list]
          rowBoundaries:
            - {field: local-title, claim: zone, operator: equals}
      refreshExternalProjections: [approved-subjects]"#
    );
    let registry = compile(&source).expect("a scoped refresh profile compiles");
    let entity = &registry.entities()["local-record"];
    let managed = entity
        .indexes
        .iter()
        .find(|(id, _)| id.starts_with("external-link:"))
        .expect("refresh link has a compiler-owned index");
    assert_eq!(
        managed.1.iter().map(String::as_str).collect::<Vec<_>>(),
        ["subject-key", "local-title"]
    );
    let statement = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == format!("entity.local-record.index.{}", managed.0))
        .expect("managed index is emitted in reviewed DDL");
    assert!(statement.sql.contains("record_id"));
    let document: serde_json::Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let paths = &document["paths"];
    assert_eq!(
        paths["/v1/external-refresh-plans/{plan}/step"]["post"]["operationId"],
        "external-refresh-plan-step",
    );
    assert_eq!(
        paths["/v1/external-refresh-plans/{plan}/hints"]["post"]["responses"]["202"]["description"],
        "Hint accepted or already admitted, without checking local matches",
    );
}
