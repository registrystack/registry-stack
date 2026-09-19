// SPDX-License-Identifier: Apache-2.0
//! Field-level encryption of restricted fields: the authoring shape, the
//! compiled storage model (envelope plus blind-index columns), the compiler
//! refusals that keep ciphertext out of every plaintext surface, and the
//! storage DDL those refusals leave behind.

#[path = "support/action_requirements.rs"]
mod action_requirements;
#[path = "support/membership_fixture.rs"]
mod membership_fixture;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_project_json, ActionInputSource, Classification, DerivedFieldSource, FieldSource,
    ModuleAssetSource, NormalizationStep,
};
use registry_breg::generated_ddl::field_lookup_index_name;
use registry_breg::{CompileFailure, CompiledRegistry};
use serde_json::{json, Value};

/// A minimal project whose `case` entity carries one encrypted restricted
/// field with a unique normalized blind-index lookup.
fn encrypted_project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"field-encryption","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://encryption.example.test"},
        "entities":[{
            "id":"case","primaryDataset":"test-dataset","route":"cases","mutationMode":"mutable",
            "fields":[
                {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"},
                {"id":"secret","type":"string","maxLength":256,"classification":"restricted","encrypted":true,
                 "lookup":{"normalization":["trim","uppercase"],"unique":true}}
            ]
        }],
        "accessProfiles":[{"id":"caseworker","default":true,"principalClaim":"principal","permissions":[{
            "entity":"case","rowBoundaries":[],"operations":["get","list","create","patch"],
            "readableFields":["label","secret"],"writableFields":["label","secret"]
        }]}]
    })
}

fn compile_value(source: &Value) -> Result<CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile_with_assets(
    source: &Value,
    assets: Vec<ModuleAssetSource>,
) -> Result<CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
}

fn expect_code(source: &Value, code: &str) {
    let Err(failure) = compile_value(source) else {
        panic!("expected a {code} diagnostic, but the project compiled")
    };
    let diagnostics = failure.diagnostics();
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "expected a {code} diagnostic, got {:?}",
        diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.code)
            .collect::<Vec<_>>()
    );
}

fn encrypted_field(registry: &CompiledRegistry) -> &registry_breg::model::CompiledField {
    &registry.entities()["case"].fields["secret"]
}

#[test]
fn encrypted_field_shape_round_trips_and_defaults_stay_absent() {
    let source: FieldSource = serde_json::from_value(json!({
        "id":"secret","type":"string","maxLength":256,"classification":"restricted",
        "encrypted":true,"lookup":{"normalization":["collapse-whitespace","remove-separators"],"unique":true}
    }))
    .unwrap();
    assert!(source.encrypted);
    let lookup = source.lookup.as_ref().unwrap();
    assert!(lookup.unique);
    assert_eq!(
        lookup.normalization,
        [
            NormalizationStep::CollapseWhitespace,
            NormalizationStep::RemoveSeparators
        ]
    );
    let value = serde_json::to_value(&source).unwrap();
    assert_eq!(value["encrypted"], json!(true));
    assert_eq!(
        value["lookup"]["normalization"],
        json!(["collapse-whitespace", "remove-separators"])
    );
    assert_eq!(value["lookup"]["unique"], json!(true));

    let plaintext: FieldSource = serde_json::from_value(json!({
        "id":"label","type":"string","maxLength":64,"classification":"internal"
    }))
    .unwrap();
    let value = serde_json::to_value(&plaintext).unwrap();
    assert!(value.get("encrypted").is_none() && value.get("lookup").is_none());
}

#[test]
fn encrypted_field_shape_refuses_unsupported_declarations() {
    for (field, because) in [
        (
            json!({"id":"secret","type":"string","maxLength":64,"classification":"internal","encrypted":true}),
            "encryption requires the restricted classification",
        ),
        (
            json!({"id":"secret","type":"string","maxLength":64,"classification":"restricted","lookup":{"unique":true}}),
            "a lookup requires an encrypted field",
        ),
        (
            json!({"id":"secret","type":"string","maxLength":64,"classification":"restricted","encrypted":true,"lookup":{"normalization":["shout"]}}),
            "the normalization vocabulary is closed",
        ),
        (
            json!({"id":"secret","type":"string","maxLength":64,"classification":"restricted","encrypted":true,"lookup":{"unique":true,"salt":"static"}}),
            "the lookup declaration carries no key material",
        ),
    ] {
        assert!(
            serde_json::from_value::<FieldSource>(field).is_err(),
            "{because}"
        );
    }
    for kind in ["boolean", "int64", "uuid", "timestamp"] {
        assert!(
            serde_json::from_value::<FieldSource>(json!({
                "id":"secret","type":kind,"classification":"restricted","encrypted":true
            }))
            .is_err(),
            "encrypted storage refuses the {kind} type"
        );
    }
    assert!(serde_json::from_value::<DerivedFieldSource>(json!({
        "id":"derived","type":"string","maxLength":8,"classification":"restricted","encrypted":true
    }))
    .is_err());
    assert!(serde_json::from_value::<DerivedFieldSource>(json!({
        "id":"derived","type":"string","maxLength":8,"classification":"restricted","lookup":{"unique":true}
    }))
    .is_err());
    assert!(serde_json::from_value::<ActionInputSource>(json!({
        "id":"secret","type":"string","maxLength":64,"classification":"restricted","encrypted":true
    }))
    .is_err());
    assert!(serde_json::from_value::<ActionInputSource>(json!({
        "id":"secret","type":"string","maxLength":64,"classification":"restricted","lookup":{"unique":true}
    }))
    .is_err());

    // The whole-project parse keeps the same value-free shape refusal.
    let mut source = encrypted_project();
    source["entities"][0]["fields"][1]["classification"] = json!("internal");
    let failure = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap_err();
    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "source.shape.invalid");
    assert_eq!(diagnostic.path, "project.entities[0].fields[1]");
}

#[test]
fn encrypted_field_compiles_to_envelope_and_blind_index_storage() {
    let registry = compile_value(&encrypted_project()).unwrap();
    let field = encrypted_field(&registry);
    let encryption = field.encryption.as_ref().unwrap();
    let blind = encryption.blind_index.as_ref().unwrap();
    assert!(blind.unique);
    assert_eq!(
        blind.normalization,
        [NormalizationStep::Trim, NormalizationStep::Uppercase]
    );
    assert!(field.physical_name.starts_with("breg_x_case_secret_"));
    assert!(blind.physical_name.starts_with("breg_i_case_secret_"));
    assert_ne!(field.physical_name, blind.physical_name);

    let entity_names = &registry.physical_names().entities["case"];
    assert_eq!(entity_names.fields["secret"], field.physical_name);
    assert_eq!(entity_names.fields["secret#lookup"], blind.physical_name);
    assert_eq!(
        entity_names.indexes["lookup:secret"],
        field_lookup_index_name("case", "secret")
    );
    assert!(field_lookup_index_name("case", "secret").starts_with("breg_lookup_"));

    let statements = &registry.ddl().statements;
    let table = statements
        .iter()
        .find(|statement| statement.id == "entity.case.table")
        .unwrap();
    assert!(table
        .sql
        .contains(&format!("{} bytea", quote(&field.physical_name))));
    assert!(table
        .sql
        .contains(&format!("{} bytea", quote(&blind.physical_name))));

    let lookup_index = statements
        .iter()
        .find(|statement| statement.id == "entity.case.field.secret.lookup-unique")
        .unwrap();
    assert_eq!(
        lookup_index.sql,
        format!(
            "CREATE UNIQUE INDEX {} ON registry_data.{} ({})",
            quote(&field_lookup_index_name("case", "secret")),
            quote(&registry.entities()["case"].physical_table),
            quote(&blind.physical_name)
        )
    );

    // The registry_source layer never exposes the envelope or its blind index.
    let source_view = statements
        .iter()
        .find(|statement| statement.id == "entity.case.source-view")
        .unwrap();
    assert!(!source_view.sql.contains(&field.physical_name));
    assert!(!source_view.sql.contains(&blind.physical_name));
    assert!(!source_view.sql.contains("\"secret\""));
    assert!(source_view.sql.contains("\"label\""));
    let compiled_entity = &registry.entities()["case"];
    assert!(!compiled_entity
        .source_relation
        .stored_fields
        .iter()
        .any(|stored| stored == "secret"));
}

fn quote(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

#[test]
fn non_unique_lookup_declares_no_unique_index_and_no_blind_column() {
    let mut source = encrypted_project();
    source["entities"][0]["fields"][1]["lookup"] = json!({"normalization": ["lowercase"]});
    let registry = compile_value(&source).unwrap();
    let field = encrypted_field(&registry);
    let blind = field
        .encryption
        .as_ref()
        .unwrap()
        .blind_index
        .as_ref()
        .unwrap();
    assert!(!blind.unique);
    let statements = &registry.ddl().statements;
    assert!(statements
        .iter()
        .all(|statement| statement.id != "entity.case.field.secret.lookup-unique"));
    // The blind-index column exists for exact-match lookup even without a
    // unique index over it.
    assert!(statements
        .iter()
        .find(|statement| statement.id == "entity.case.table")
        .unwrap()
        .sql
        .contains(&format!("{} bytea", quote(&blind.physical_name))));
}

#[test]
fn encrypted_columns_carry_no_pattern_check() {
    let mut source = encrypted_project();
    source["entities"][0]["fields"][1]["pattern"] = json!("^[0-9]{13}$");
    let registry = compile_value(&source).unwrap();
    assert!(registry
        .ddl()
        .statements
        .iter()
        .any(|statement| statement.id == "entity.case.field.secret.lookup-unique"));
    assert!(registry
        .ddl()
        .statements
        .iter()
        .all(|statement| statement.id != "entity.case.field.secret.pattern"));
    // The runtime value contract keeps the authored pattern.
    assert_eq!(
        encrypted_field(&registry).pattern.as_deref(),
        Some("^[0-9]{13}$")
    );
}

#[test]
fn encrypted_field_refuses_valid_time_role_and_inconsistent_classification() {
    let mut source = encrypted_project();
    source["entities"][0]["fields"][1]["validTimeRole"] = json!("valid_from");
    expect_code(&source, "field.encrypted.valid_time_refused");

    // The compiler keeps its own refusal for programmatically assembled
    // contracts that skip the value-free shape parse.
    let mut project =
        parse_project_json(&serde_json::to_vec(&encrypted_project()).unwrap()).unwrap();
    project.entities[0].fields[1].classification = Classification::Internal;
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "field.encrypted.classification_invalid"));
}

#[test]
fn encrypted_field_refuses_storage_constraints_and_authored_indexes() {
    let mut constrained = encrypted_project();
    constrained["entities"][0]["constraints"] =
        json!([{"id":"secret-unique","kind":"unique","fields":["secret"]}]);
    expect_code(&constrained, "constraint.field.encrypted");

    let mut indexed = encrypted_project();
    indexed["entities"][0]["indexes"] = json!([{"id":"secret-index","fields":["secret"]}]);
    expect_code(&indexed, "index.fields.encrypted");
}

#[test]
fn encrypted_field_refuses_processing_row_boundaries_and_lookupless_selectors() {
    let mut processing = encrypted_project();
    processing["accessProfiles"][0]["permissions"][0]["filterableFields"] = json!(["secret"]);
    processing["accessProfiles"][0]["permissions"][0]["sortableFields"] = json!(["secret"]);
    expect_code(&processing, "access_profile.processing.encrypted");

    let mut boundary = encrypted_project();
    boundary["accessProfiles"][0]["permissions"][0]["rowBoundaries"] =
        json!([{"field":"secret","claim":"secrets","operator":"equals"}]);
    expect_code(&boundary, "access_profile.row_boundary.encrypted");

    // A selector profile over an encrypted field is exact-match lookup and
    // must declare the blind index that serves it.
    let mut selector = encrypted_project();
    selector["entities"][0]["selectorProfiles"] = json!([{"id":"by-secret","fields":["secret"]}]);
    selector["entities"][0]["fields"][1]
        .as_object_mut()
        .unwrap()
        .remove("lookup");
    expect_code(&selector, "selector_profile.encrypted_lookup_required");
    // Declaring the lookup removes the refusal.
    selector["entities"][0]["fields"][1]["lookup"] =
        json!({"normalization":["uppercase"],"unique":true});
    compile_value(&selector).unwrap();
}

#[test]
fn encrypted_fields_refuse_event_projection_and_conditions() {
    let mut projected = encrypted_project();
    projected["entities"][0]["events"] =
        json!([{"id":"secret-seen","trigger":"created","projection":["secret"]}]);
    expect_code(&projected, "event.projection.encrypted");

    let mut conditioned = encrypted_project();
    conditioned["entities"][0]["events"] = json!([{
        "id":"secret-seen","trigger":"created","projection":["label"],
        "when":{"kind":"fields","afterEquals":{"secret":"canary"}}
    }]);
    expect_code(&conditioned, "event.when.encrypted");

    let mut changed = encrypted_project();
    changed["entities"][0]["events"] = json!([{
        "id":"secret-seen","trigger":"patched","projection":["label"],
        "when":{"kind":"fields","changed":["secret"]}
    }]);
    expect_code(&changed, "event.when.encrypted");
}

#[test]
fn derived_sql_cannot_reference_encrypted_columns() {
    let mut source = encrypted_project();
    source["entities"][0]["derived"] = json!([{
        "id":"case-facts","sql":"sql/case-facts.sql","key":"id",
        "fields":[{"id":"fact-count","type":"int64","classification":"internal"}]
    }]);
    let refusing = b"SELECT h.id AS id, count(*) AS fact_count \
         FROM registry_source.case h WHERE h.secret IS NOT NULL GROUP BY h.id"
        .to_vec();
    let failure = compile_with_assets(
        &source,
        vec![ModuleAssetSource {
            module: None,
            path: "sql/case-facts.sql".into(),
            bytes: refusing,
        }],
    )
    .unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "derived.sql.encrypted_column"));

    let accepting = compile_with_assets(
        &source,
        vec![ModuleAssetSource {
            module: None,
            path: "sql/case-facts.sql".into(),
            bytes: b"SELECT h.id AS id, count(*) AS fact_count FROM registry_source.case h \
                    GROUP BY h.id"
                .to_vec(),
        }],
    )
    .unwrap();
    assert!(accepting.entities()["case"].fields.contains_key("secret"));
}

fn change_request_project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"request-encryption","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "evidenceProviders":[{"id":"laboratory","contracts":"evidence/contracts.json","subjectResolution":"trusted-provider-exact-selector"}],
        "entities":[{
            "id":"lot","primaryDataset":"test-dataset","route":"lots","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
                {"id":"owner-reference","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                {"id":"lot-reference","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                {"id":"active","type":"boolean","required":true,"classification":"restricted"},
                {"id":"release-state","type":"string","maxLength":16,"required":true,"classification":"restricted"}
            ]
        },{
            "id":"release-request","primaryDataset":"test-dataset","route":"release-requests","mutationMode":"mutable",
            "fields":[
                {"id":"lot","type":"reference","target":"lot","required":true,"classification":"restricted"},
                {"id":"owner-reference","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                {"id":"report-reference","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                {"id":"release-state","type":"string","maxLength":16,"required":true,"classification":"restricted"},
                {"id":"valid-from","type":"date","required":true,"classification":"restricted"},
                {"id":"valid-through","type":"date","required":true,"classification":"restricted"}
            ],
            "changeRequest":{
                "effects":[{"id":"release","target":{"fromField":"lot"}, "operation":"patch", "set":{"release-state":{"fromField":"release-state"}}}],
                "review":{"stages":[{"id":"review","approvals":1}]},
                "application":{"mode":"manual","preconditions":{
                    "request":[
                        {"field":"valid-from","currentDate":"on_or_before"},
                        {"field":"valid-through","currentDate":"on_or_after"}
                    ],
                    "targets":[{"id":"lot","entity":"lot","fromField":"lot","requires":[
                        {"field":"owner-reference","equalsFromRequestField":"owner-reference"},
                        {"field":"active","equals":true}
                    ]}],
                    "evidence":[{
                        "id":"release-check","provider":"laboratory","requirement":"urn:example:requirement:lot-release:v1",
                        "subjects":{"subject":{"profile":"lot-owner-v1","selectors":{
                            "lot-reference":{"source":"target_field","target":"lot","field":"lot-reference"},
                            "owner-reference":{"source":"request_field","field":"owner-reference"}
                        }}},
                        "requires":[
                            {"output":"report-reference","equalsFromRequestField":"report-reference"},
                            {"output":"germination","atLeast":9000}
                        ],
                        "maximumObservationAgeSeconds":300
                    }]
                }}
            }
        }],
        "accessProfiles":[{"id":"reviewer","default":true,"principalClaim":"principal","permissions":[{
            "entity":"release-request",
            "operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],
            "readableFields":["lot","owner-reference","report-reference","release-state","valid-from","valid-through"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"lot","readableFields":["release-state"],"rowBoundaries":[]}]}],
            "applyTargets":[{"entity":"lot","rowBoundaries":[]}],"rowBoundaries":[]
        }]}]
    })
}

fn evidence_contracts() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "registry.evidence-client-contracts/v1",
        "assuranceProfile": "local",
        "audience": "urn:example:seed-registry",
        "issuedBy": "urn:example:laboratory",
        "providedBy": "urn:example:evidence-service",
        "definitions": [{
            "handle": "lot-release",
            "requirement": "urn:example:requirement:lot-release:v1",
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "kind": "criterion",
            "evidenceType": "urn:example:evidence:lot-release:v1",
            "purpose": "lot-release",
            "responseFormats": ["signed-jws"],
            "referenceFrameworks": ["urn:example:framework:seed:v1"],
            "subjects": [{
                "role": "subject", "cardinality": "one",
                "selector": {
                    "profile": "lot-owner-v1", "valueOrigin": "request",
                    "fields": [
                        {"type":"string","name":"lot-reference","minimumBytes":1,"maximumBytes":64},
                        {"type":"string","name":"owner-reference","minimumBytes":1,"maximumBytes":64}
                    ]
                }
            }],
            "concepts": [
                {"handle":"report-reference","concept":"urn:example:concept:report","required":true,"form":"string"},
                {"handle":"germination","concept":"urn:example:concept:germination","required":true,"form":"integer"}
            ]
        }]
    }))
    .unwrap()
}

fn compile_request(source: &Value) -> Result<CompiledRegistry, CompileFailure> {
    compile_with_assets(
        source,
        vec![ModuleAssetSource {
            module: None,
            path: "evidence/contracts.json".into(),
            bytes: evidence_contracts(),
        }],
    )
}

fn expect_request_code(source: &Value, code: &str) {
    let Err(failure) = compile_request(source) else {
        panic!("expected a {code} diagnostic, but the project compiled")
    };
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "expected a {code} diagnostic, got {:?}",
        failure
            .diagnostics()
            .iter()
            .map(|diagnostic| &diagnostic.code)
            .collect::<Vec<_>>()
    );
}

#[test]
fn change_request_paths_refuse_encrypted_fields() {
    // The unmutated contract compiles: encryption is a declaration, not a
    // standing refusal.
    compile_request(&change_request_project()).unwrap();

    // The request entity's encrypted fields cannot serve predicates, request
    // bindings, evidence requirements, or selector subjects.
    let mut request_encrypted = change_request_project();
    for field in [1usize, 2, 4] {
        request_encrypted["entities"][1]["fields"][field]["encrypted"] = json!(true);
        request_encrypted["entities"][1]["fields"][field]["lookup"] =
            json!({"normalization":["uppercase"]});
    }
    for code in [
        "change_request.preconditions.predicate_field_encrypted",
        "change_request.preconditions.predicate_request_field_encrypted",
        "change_request.preconditions.evidence_requirement_encrypted",
        "change_request.preconditions.selector_field_encrypted",
    ] {
        expect_request_code(&request_encrypted, code);
    }

    // A planner cannot take an encrypted request field.
    let mut planned = change_request_project();
    planned["entities"][1]["fields"][1]["encrypted"] = json!(true);
    planned["entities"][1]["fields"][1]["lookup"] = json!({"normalization":["uppercase"]});
    planned["entities"][1]["changeRequest"]["planner"] = json!({
        "kind":"rhai","script":"planners/release.rhai","abi":"registry.change-request-plan/v1",
        "requestFields":["owner-reference"],
        "writes":[{"target":{"fromField":"lot"},"operation":"patch","fields":["release-state"]}]
    });
    let failure = compile_request(&planned).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.planner.request_field_encrypted"));

    // A target selector cannot bind an encrypted stored field either.
    let mut target_selector = change_request_project();
    target_selector["entities"][0]["fields"][1]["encrypted"] = json!(true);
    target_selector["entities"][0]["fields"][1]["lookup"] = json!({"normalization":["uppercase"]});
    expect_request_code(
        &target_selector,
        "change_request.preconditions.selector_field_encrypted",
    );
}

#[test]
fn membership_principal_field_cannot_be_encrypted() {
    let mut source = membership_fixture::source("facility");
    source["entities"][1]["fields"][1]["encrypted"] = json!(true);
    let failure = membership_fixture::compile(&source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access.membership.principal_encrypted"));
}

#[test]
fn action_requirements_cannot_name_encrypted_fields() {
    let mut source = action_requirements::project();
    source["entities"][0]["fields"][1]["encrypted"] = json!(true);
    source["entities"][0]["fields"][1]["lookup"] = json!({"normalization":["uppercase"]});
    source["actions"][0]["requires"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "input":"parent","field":"zone","equals":"north"
        }));
    let failure = compile_value(&source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.requires.field_encrypted"));
}

#[cfg(feature = "runtime")]
#[test]
fn encryption_flip_change_sets_classify_without_a_physical_rename() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, compiled_registry_change_set,
        CompiledRegistryChangeClass as Class, CompiledRegistryChangeCode as Code,
    };

    let compile = |lookup: Option<Value>| {
        let mut source = encrypted_project();
        match lookup {
            Some(lookup) => {
                source["entities"][0]["fields"][1]["lookup"] = lookup;
                source["entities"][0]["fields"][1]["encrypted"] = json!(true);
            }
            None => {
                source["entities"][0]["fields"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("encrypted");
                source["entities"][0]["fields"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("lookup");
            }
        }
        compile_value(&source).unwrap()
    };
    let prior = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let plaintext = compile(None);
    let encrypted_unique = compile(Some(json!({"normalization":["uppercase"],"unique":true})));
    let encrypted_plain_lookup = compile(Some(json!({"normalization":["uppercase"]})));
    let mut no_lookup = encrypted_project();
    no_lookup["entities"][0]["fields"][1]
        .as_object_mut()
        .unwrap()
        .remove("lookup");
    let encrypted_no_lookup = compile_value(&no_lookup).unwrap();

    // Turning encryption on rekeys storage behind a reviewed backfill and is
    // never the compiler-applicable physical rename it replaces.
    let flip_on = compiled_registry_change_set(&plaintext, &encrypted_unique, prior);
    assert!(flip_on
        .changes
        .iter()
        .any(|change| change.code == Code::FieldEncryptionChanged
            && change.class == Class::DataBackfillRequired));
    assert!(flip_on
        .changes
        .iter()
        .all(|change| change.code != Code::FieldPhysicalNameChanged));
    assert!(change_set_to_applicable_migration_plan(&flip_on).is_err());

    // Turning encryption off discards the envelope and is destructive.
    let flip_off = compiled_registry_change_set(&encrypted_unique, &plaintext, prior);
    assert!(flip_off
        .changes
        .iter()
        .any(|change| change.code == Code::FieldEncryptionChanged
            && change.class == Class::DestructiveOrIrreversible));
    assert!(flip_off
        .changes
        .iter()
        .all(|change| change.code != Code::FieldPhysicalNameChanged));
    assert!(change_set_to_applicable_migration_plan(&flip_off).is_err());

    // Lookup changes on an already-encrypted field keep the envelope: gaining
    // or rekeying the blind index needs a backfill, losing the lookup or its
    // uniqueness retires storage.
    let lookup_on = compiled_registry_change_set(&encrypted_plain_lookup, &encrypted_unique, prior);
    assert!(lookup_on
        .changes
        .iter()
        .any(|change| change.code == Code::FieldLookupChanged
            && change.class == Class::DataBackfillRequired));
    let lookup_off =
        compiled_registry_change_set(&encrypted_unique, &encrypted_plain_lookup, prior);
    assert!(lookup_off
        .changes
        .iter()
        .any(|change| change.code == Code::FieldLookupChanged
            && change.class == Class::DestructiveOrIrreversible));
    let rekeyed = compile(Some(json!({"normalization":["lowercase"],"unique":true})));
    let lookup_rekeyed = compiled_registry_change_set(&encrypted_unique, &rekeyed, prior);
    assert!(lookup_rekeyed
        .changes
        .iter()
        .any(|change| change.code == Code::FieldLookupChanged
            && change.class == Class::DataBackfillRequired));
    let lookup_lost =
        compiled_registry_change_set(&encrypted_plain_lookup, &encrypted_no_lookup, prior);
    assert!(lookup_lost
        .changes
        .iter()
        .any(|change| change.code == Code::FieldLookupChanged
            && change.class == Class::DestructiveOrIrreversible));
    assert!(
        compiled_registry_change_set(&encrypted_unique, &encrypted_unique, prior)
            .changes
            .is_empty()
    );
}
