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
    ModuleAssetSource, NormalizationStep, MAX_ENCRYPTED_FIELDS_PER_ENTITY,
    MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES, MAX_ENCRYPTED_FIELD_STRING_CHARACTERS,
    MAX_FIELD_LOOKUP_NORMALIZATION_STEPS,
};
use registry_breg::diagnostics::DiagnosticSeverity;
use registry_breg::generated_ddl::field_lookup_index_name;
use registry_breg::{CompileFailure, CompiledRegistry};
use serde_json::{json, Value};

/// A minimal project whose `case` entity carries one encrypted restricted
/// field with a unique normalized blind-index lookup.
fn encrypted_project() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"field-encryption","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://encryption.example.test"},
        "recordTypes":[{
            "id":"case","primaryDataset":"test-dataset","route":"cases","mutationMode":"mutable",
            "fields":[
                {"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"},
                {"id":"secret","type":"string","maximumLength":256,"classification":"restricted","encrypted":true,
                 "lookup":{"normalization":["trim","uppercase"],"unique":true}}
            ]
        }],
        "accessProfiles":[{"id":"caseworker","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
            "recordType":"case","rowBoundaries":"unrestricted","operations":["get","list","create","patch"],
            "readableFields":["label","secret"],"writableFields":["label","secret"]
        }]}}]
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

fn assert_retained_authoring_finding(failure: &CompileFailure) {
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Finding
            && diagnostic.code == "breg.package.identity-missing"
            && diagnostic.path == "project.package"
    }));
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
        "id":"secret","type":"string","maximumLength":256,"classification":"restricted",
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
        "id":"label","type":"string","maximumLength":64,"classification":"internal"
    }))
    .unwrap();
    let value = serde_json::to_value(&plaintext).unwrap();
    assert!(value.get("encrypted").is_none() && value.get("lookup").is_none());
}

#[test]
fn encrypted_field_shape_refuses_unsupported_declarations() {
    for (field, because) in [
        (
            json!({"id":"secret","type":"string","maximumLength":64,"classification":"internal","encrypted":true}),
            "encryption requires the restricted classification",
        ),
        (
            json!({"id":"secret","type":"string","maximumLength":64,"classification":"restricted","lookup":{"unique":true}}),
            "a lookup requires an encrypted field",
        ),
        (
            json!({"id":"secret","type":"string","maximumLength":64,"classification":"restricted","encrypted":true,"lookup":{"normalization":["shout"]}}),
            "the normalization vocabulary is closed",
        ),
        (
            json!({"id":"secret","type":"string","maximumLength":64,"classification":"restricted","encrypted":true,"lookup":{"unique":true,"salt":"static"}}),
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
        "id":"derived","type":"string","maximumLength":8,"classification":"restricted","encrypted":true
    }))
    .is_err());
    assert!(serde_json::from_value::<DerivedFieldSource>(json!({
        "id":"derived","type":"string","maximumLength":8,"classification":"restricted","lookup":{"unique":true}
    }))
    .is_err());
    assert!(serde_json::from_value::<ActionInputSource>(json!({
        "id":"secret","type":"string","maximumLength":64,"classification":"restricted","encrypted":true
    }))
    .is_err());
    assert!(serde_json::from_value::<ActionInputSource>(json!({
        "id":"secret","type":"string","maximumLength":64,"classification":"restricted","lookup":{"unique":true}
    }))
    .is_err());

    // The whole-project parse keeps the same value-free shape refusal.
    let mut source = encrypted_project();
    source["recordTypes"][0]["fields"][1]["classification"] = json!("internal");
    let failure = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap_err();
    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(diagnostic.path, "project.recordTypes[0].fields[1]");
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
    source["recordTypes"][0]["fields"][1]["lookup"] = json!({"normalization": ["lowercase"]});
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
fn encrypted_field_refuses_pattern_with_a_pinned_diagnostic() {
    let mut source = encrypted_project();
    source["recordTypes"][0]["fields"][1]["pattern"] = json!("^[0-9]{13}$");
    let failure = compile_value(&source).unwrap_err();
    assert_retained_authoring_finding(&failure);
    let diagnostics = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1, "the refusal stays stable and focused");
    let diagnostic = diagnostics[0];
    assert_eq!(diagnostic.code, "breg.field.encrypted-pattern-refused");
    assert_eq!(diagnostic.path, "recordTypes[case].fields[secret].pattern");
    assert_eq!(
        diagnostic.message,
        "an encrypted field cannot declare pattern in Phase 1; remove pattern or store the field as plaintext"
    );
}

#[test]
fn encrypted_field_bounds_fit_the_phase_one_seal_limit() {
    let mut string = encrypted_project();
    string["recordTypes"][0]["fields"][1]["maximumLength"] =
        json!(MAX_ENCRYPTED_FIELD_STRING_CHARACTERS);
    compile_value(&string).expect("the worst-case UTF-8 string boundary compiles");

    string["recordTypes"][0]["fields"][1]["maximumLength"] =
        json!(MAX_ENCRYPTED_FIELD_STRING_CHARACTERS + 1);
    let failure = compile_value(&string).expect_err("an oversized encrypted string is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.encrypted-size-bound-exceeds-seal-limit")
        .expect("the encrypted string bound diagnostic is present");
    assert_eq!(
        diagnostic.path,
        "recordTypes[case].fields[secret].maximumLength"
    );
    assert_eq!(
        diagnostic.message,
        "an encrypted string or text field maximumLength must be at most 16384 characters so every valid UTF-8 value fits the 65536-byte Phase 1 seal limit"
    );

    let mut text = encrypted_project();
    text["recordTypes"][0]["fields"][1]["type"] = json!("text");
    text["recordTypes"][0]["fields"][1]["maximumLength"] =
        json!(MAX_ENCRYPTED_FIELD_STRING_CHARACTERS + 1);
    expect_code(&text, "breg.field.encrypted-size-bound-exceeds-seal-limit");

    let mut structured = encrypted_project();
    structured["recordTypes"][0]["fields"][1] = json!({
        "id":"secret", "type":"structured",
        "maximumBytes":MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES,
        "schema":{"type":"object","additionalProperties":false},
        "classification":"restricted", "encrypted":true
    });
    compile_value(&structured).expect("the canonical structured byte boundary compiles");

    structured["recordTypes"][0]["fields"][1]["maximumBytes"] =
        json!(MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES + 1);
    let failure =
        compile_value(&structured).expect_err("an oversized encrypted structured field is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.encrypted-size-bound-exceeds-seal-limit")
        .expect("the encrypted structured bound diagnostic is present");
    assert_eq!(
        diagnostic.path,
        "recordTypes[case].fields[secret].maximumBytes"
    );
    assert_eq!(
        diagnostic.message,
        "an encrypted structured field maximumBytes must be at most 65536 bytes to fit the Phase 1 seal limit"
    );
}

#[test]
fn encrypted_field_count_bounds_snapshot_envelope_overhead() {
    let mut source = encrypted_project();
    let fields = source["recordTypes"][0]["fields"].as_array_mut().unwrap();
    for index in 1..=MAX_ENCRYPTED_FIELDS_PER_ENTITY {
        fields.push(json!({
            "id":format!("secret-{index}"),
            "type":"date",
            "classification":"restricted",
            "encrypted":true
        }));
    }
    expect_code(&source, "breg.record-type.encrypted-fields-too-many");

    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .pop();
    compile_value(&source).expect("the Phase 1 encrypted-field ceiling remains usable");
}

#[test]
fn encrypted_lookup_refuses_structured_values_and_unbounded_normalization() {
    let mut structured = encrypted_project();
    structured["recordTypes"][0]["fields"][1] = json!({
        "id":"secret", "type":"structured", "maximumBytes":1024,
        "schema":{"type":"object","additionalProperties":false},
        "classification":"restricted", "encrypted":true,
        "lookup":{"normalization":["trim"]}
    });
    let failure = compile_value(&structured).expect_err("a structured encrypted lookup is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.encrypted-lookup-type-unsupported")
        .expect("the structured lookup diagnostic is present");
    assert_eq!(diagnostic.path, "recordTypes[case].fields[secret].lookup");
    assert_eq!(
        diagnostic.message,
        "a structured encrypted field cannot declare lookup in Phase 1; remove lookup or use an encrypted string field for exact-match lookup"
    );

    let mut bounded = encrypted_project();
    bounded["recordTypes"][0]["fields"][1]["lookup"]["normalization"] =
        json!(
            std::iter::repeat_n("trim", MAX_FIELD_LOOKUP_NORMALIZATION_STEPS).collect::<Vec<_>>()
        );
    compile_value(&bounded).expect("the normalization-step boundary compiles");

    bounded["recordTypes"][0]["fields"][1]["lookup"]["normalization"] = json!(std::iter::repeat_n(
        "trim",
        MAX_FIELD_LOOKUP_NORMALIZATION_STEPS + 1
    )
    .collect::<Vec<_>>());
    let failure =
        compile_value(&bounded).expect_err("an unbounded normalization pipeline is refused");
    assert_retained_authoring_finding(&failure);
    let diagnostics = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1, "the refusal stays stable and focused");
    let diagnostic = diagnostics[0];
    assert_eq!(
        diagnostic.code,
        "breg.field.encrypted-lookup-normalization-too-long"
    );
    assert_eq!(
        diagnostic.path,
        "recordTypes[case].fields[secret].lookup.normalization"
    );
    assert_eq!(
        diagnostic.message,
        "an encrypted field lookup may declare at most 8 normalization steps"
    );
}

#[test]
fn encrypted_field_refuses_valid_time_role_and_inconsistent_classification() {
    let mut source = encrypted_project();
    source["recordTypes"][0]["fields"][1]["validTimeRole"] = json!("valid-from");
    expect_code(&source, "breg.field.encrypted-valid-time-refused");

    // The compiler keeps its own refusal for programmatically assembled
    // contracts that skip the value-free shape parse.
    let mut project =
        parse_project_json(&serde_json::to_vec(&encrypted_project()).unwrap()).unwrap();
    project.entities[0].fields[1].classification = Classification::Internal;
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.field.encrypted-classification-invalid"));
}

#[test]
fn encrypted_field_refuses_storage_constraints_and_authored_indexes() {
    let mut constrained = encrypted_project();
    constrained["recordTypes"][0]["constraints"] =
        json!([{"id":"secret-unique","type":"unique","fields":["secret"]}]);
    expect_code(&constrained, "breg.constraint.field-encrypted");

    let mut indexed = encrypted_project();
    indexed["recordTypes"][0]["indexes"] = json!([{"id":"secret-index","fields":["secret"]}]);
    expect_code(&indexed, "breg.index.fields-encrypted");
}

#[test]
fn encrypted_field_refuses_processing_row_boundaries_and_lookupless_selectors() {
    let mut processing = encrypted_project();
    processing["accessProfiles"][0]["permissions"]["records"][0]["filterableFields"] =
        json!(["secret"]);
    processing["accessProfiles"][0]["permissions"]["records"][0]["sortableFields"] =
        json!(["secret"]);
    let failure = compile_value(&processing).expect_err("encrypted processing is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.access-profile.processing-encrypted")
        .expect("encrypted processing diagnostic");
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=case].accessProfiles[id=caseworker].filterableFields[field=secret]"
    );

    let mut boundary = encrypted_project();
    boundary["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!([{"field":"secret","claim":"secrets","operator":"equals"}]);
    expect_code(&boundary, "breg.access-profile.row-boundary-encrypted");

    // A selector profile over an encrypted field is exact-match lookup and
    // must declare the blind index that serves it.
    let mut selector = encrypted_project();
    selector["recordTypes"][0]["selectorProfiles"] =
        json!([{"id":"by-secret","fields":["secret"]}]);
    selector["recordTypes"][0]["fields"][1]
        .as_object_mut()
        .unwrap()
        .remove("lookup");
    expect_code(&selector, "breg.selector-profile.encrypted-lookup-required");
    // Declaring the lookup removes the refusal.
    selector["recordTypes"][0]["fields"][1]["lookup"] =
        json!({"normalization":["uppercase"],"unique":true});
    compile_value(&selector).unwrap();
}

#[test]
fn encrypted_fields_refuse_event_projection_and_conditions() {
    let mut projected = encrypted_project();
    projected["recordTypes"][0]["hooks"] =
        json!([{"id":"secret-seen","phase":"after","trigger":"created","projection":["secret"]}]);
    expect_code(&projected, "breg.event.projection-encrypted");

    let mut conditioned = encrypted_project();
    conditioned["recordTypes"][0]["hooks"] = json!([{
        "id":"secret-seen","phase":"after","trigger":"created","projection":["label"],
        "when":{"type":"fields","afterEquals":{"secret":"canary"}}
    }]);
    expect_code(&conditioned, "breg.event.when-encrypted");

    let mut changed = encrypted_project();
    changed["recordTypes"][0]["hooks"] = json!([{
        "id":"secret-seen","phase":"after","trigger":"patched","projection":["label"],
        "when":{"type":"fields","changed":["secret"]}
    }]);
    expect_code(&changed, "breg.event.when-encrypted");
}

#[test]
fn derived_sql_cannot_reference_encrypted_columns() {
    let mut source = encrypted_project();
    source["recordTypes"][0]["derived"] = json!([{
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
        .any(|diagnostic| diagnostic.code == "breg.derived.sql-encrypted-column"));

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

#[test]
fn derived_sql_resolves_qualified_columns_to_their_source_relation() {
    let mut source = encrypted_project();
    source["recordTypes"].as_array_mut().unwrap().push(json!({
        "id":"public-case","primaryDataset":"test-dataset","route":"public-cases",
        "mutationMode":"mutable",
        "fields":[
            {"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"},
            {"id":"secret","type":"string","maximumLength":256,"classification":"restricted"}
        ]
    }));
    source["recordTypes"][0]["derived"] = json!([{
        "id":"case-facts","sql":"sql/case-facts.sql","key":"id",
        "fields":[{"id":"fact-count","type":"int64","classification":"internal"}]
    }]);

    for sql in [
        "SELECT public_case.id AS id, count(public_case.secret) AS fact_count \
         FROM registry_source.public_case GROUP BY public_case.id",
        "SELECT p.id AS id, count(p.secret) AS fact_count \
         FROM registry_source.public_case p GROUP BY p.id",
    ] {
        compile_with_assets(
            &source,
            vec![ModuleAssetSource {
                module: None,
                path: "sql/case-facts.sql".into(),
                bytes: sql.as_bytes().to_vec(),
            }],
        )
        .expect("the qualified secret name belongs to the plaintext source relation");
    }

    for sql in [
        "WITH visible AS (\
           SELECT p.id, p.secret FROM registry_source.public_case p\
         ) \
         SELECT visible.id AS id, count(visible.secret) AS fact_count \
         FROM visible GROUP BY visible.id",
        "WITH visible AS (\
           SELECT p.id AS id, p.secret AS secret FROM registry_source.public_case p\
         ) \
         SELECT visible.id AS id, count(visible.secret) AS fact_count \
         FROM visible GROUP BY visible.id",
        "WITH visible(public_id, public_secret) AS (\
           SELECT p.id, p.secret FROM registry_source.public_case p\
         ) \
         SELECT v.public_id AS id, count(v.public_secret) AS fact_count \
         FROM visible v GROUP BY v.public_id",
    ] {
        compile_with_assets(
            &source,
            vec![ModuleAssetSource {
                module: None,
                path: "sql/case-facts.sql".into(),
                bytes: sql.as_bytes().to_vec(),
            }],
        )
        .expect("a declared CTE output keeps its plaintext source identity");
    }

    for sql in [
        "WITH hidden AS (\
           SELECT h.id AS id, h.secret AS secret FROM registry_source.case h\
         ) \
         SELECT hidden.id AS id, count(hidden.secret) AS fact_count \
         FROM hidden GROUP BY hidden.id",
        "WITH visible AS (\
           SELECT p.secret, p.secret FROM registry_source.public_case p\
         ) \
         SELECT visible.secret AS id, count(*) AS fact_count FROM visible \
         GROUP BY visible.secret",
        "WITH visible AS (SELECT p.* FROM registry_source.public_case p) \
         SELECT visible.id AS id, count(visible.secret) AS fact_count \
         FROM visible GROUP BY visible.id",
    ] {
        let failure = compile_with_assets(
            &source,
            vec![ModuleAssetSource {
                module: None,
                path: "sql/case-facts.sql".into(),
                bytes: sql.as_bytes().to_vec(),
            }],
        )
        .expect_err("encrypted, duplicate, and wildcard CTE outputs stay fail-closed");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.derived.sql-encrypted-column"));
    }
}

fn proposal_project() -> Value {
    let mut source = encrypted_project();
    source["recordTypes"][0]["mutationPolicy"] = json!({"patch":"proposal-required"});
    source["actions"] = json!([{"id":"correct-case","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"},"reviewContext":{"id":"case-context","fields":{"currentLabel":{"type":"record","input":"case","field":"label"}}}}},"inputs":[{"id":"case","type":"reference","target":"case","required":true,"classification":"restricted"},{"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"}],"plan":{"type":"fixed","effects":[{"id":"case","target":{"fromInput":"case"},"operation":"patch","set":{"label":{"fromInput":"label"}}}]}}]);
    let permissions = &mut source["accessProfiles"][0]["permissions"];
    permissions["records"][0]["operations"] = json!(["get", "list"]);
    permissions["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("writableFields");
    permissions["actions"] = json!([{"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]);
    permissions["proposals"] = json!([{"action":"correct-case","operations":["get","edit","submit","apply"],"ownership":"caller","readableInputs":["case","label"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]);
    source
}

#[test]
fn native_proposal_context_refuses_encrypted_record_fields() {
    let mut source = proposal_project();
    compile_value(&source)
        .expect("plaintext context can coexist with unchanged encrypted Record fields");
    source["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["currentLabel"]
        ["field"] = json!("secret");
    expect_code(&source, "breg.proposal.context-mapping-invalid");
}

#[test]
fn native_proposal_inputs_do_not_accept_persisted_record_encryption_members() {
    let mut source = proposal_project();
    source["actions"][0]["inputs"][1]["encrypted"] = json!(true);
    let failure = parse_project_json(&serde_json::to_vec(&source).unwrap())
        .expect_err("Proposal inputs are closed ephemeral Action inputs");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "config.invalid-value"
                && diagnostic.path == "project.actions[0].inputs[1]"
                && diagnostic
                    .message
                    .contains("without validTimeRole, pattern, encrypted, or lookup")),
        "{failure:?}"
    );
}

#[test]
fn membership_principal_field_cannot_be_encrypted() {
    let mut source = membership_fixture::source("facility");
    source["recordTypes"][1]["fields"][1]["encrypted"] = json!(true);
    let failure = membership_fixture::compile(&source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access.membership-principal-encrypted"));
}

#[test]
fn action_requirements_cannot_name_encrypted_fields() {
    let mut source = action_requirements::project();
    source["recordTypes"][0]["fields"][1]["encrypted"] = json!(true);
    source["recordTypes"][0]["fields"][1]["lookup"] = json!({"normalization":["uppercase"]});
    source["actions"][0]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "input":"parent","field":"zone","equals":"north"
        }));
    let failure = compile_value(&source).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.commit_guards.targets-field-encrypted"));
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
                source["recordTypes"][0]["fields"][1]["lookup"] = lookup;
                source["recordTypes"][0]["fields"][1]["encrypted"] = json!(true);
            }
            None => {
                source["recordTypes"][0]["fields"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("encrypted");
                source["recordTypes"][0]["fields"][1]
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
    no_lookup["recordTypes"][0]["fields"][1]
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

    // Phase 1 cannot open envelopes into a replacement plaintext column, so
    // turning encryption off is rejected rather than delegated to authored SQL.
    let flip_off = compiled_registry_change_set(&encrypted_unique, &plaintext, prior);
    assert!(flip_off
        .changes
        .iter()
        .any(|change| change.code == Code::FieldEncryptionChanged
            && change.class == Class::Unsupported));
    assert!(flip_off
        .changes
        .iter()
        .all(|change| change.code != Code::FieldPhysicalNameChanged));
    assert!(change_set_to_applicable_migration_plan(&flip_off).is_err());

    // Existing envelopes are the only source values, so every lookup change on
    // an already-encrypted field stays unsupported until a dedicated keyed
    // blind-index backfill exists.
    let lookup_on = compiled_registry_change_set(&encrypted_plain_lookup, &encrypted_unique, prior);
    assert!(lookup_on.changes.iter().any(
        |change| change.code == Code::FieldLookupChanged && change.class == Class::Unsupported
    ));
    let lookup_off =
        compiled_registry_change_set(&encrypted_unique, &encrypted_plain_lookup, prior);
    assert!(lookup_off.changes.iter().any(
        |change| change.code == Code::FieldLookupChanged && change.class == Class::Unsupported
    ));
    let rekeyed = compile(Some(json!({"normalization":["lowercase"],"unique":true})));
    let lookup_rekeyed = compiled_registry_change_set(&encrypted_unique, &rekeyed, prior);
    assert!(lookup_rekeyed.changes.iter().any(
        |change| change.code == Code::FieldLookupChanged && change.class == Class::Unsupported
    ));
    let lookup_lost =
        compiled_registry_change_set(&encrypted_plain_lookup, &encrypted_no_lookup, prior);
    assert!(lookup_lost.changes.iter().any(
        |change| change.code == Code::FieldLookupChanged && change.class == Class::Unsupported
    ));

    // Existing envelopes cannot be handed to authored SQL for conversion.
    // A keyed engine conversion must exist before an encrypted field may
    // change its authored type.
    let mut structured = encrypted_project();
    structured["recordTypes"][0]["fields"][1] = json!({
        "id":"secret", "type":"structured", "maximumBytes":1024,
        "schema":{"type":"object","additionalProperties":false},
        "classification":"restricted", "encrypted":true
    });
    let encrypted_structured = compile_value(&structured).unwrap();
    let type_change =
        compiled_registry_change_set(&encrypted_no_lookup, &encrypted_structured, prior);
    assert!(type_change.changes.iter().any(|change| {
        change.code == Code::FieldTypeChanged && change.class == Class::Unsupported
    }));
    assert!(change_set_to_applicable_migration_plan(&type_change).is_err());

    let mut without_secret = encrypted_project();
    without_secret["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("fields are an array")
        .retain(|field| field["id"] != "secret");
    without_secret["accessProfiles"][0]["permissions"]["records"][0]["readableFields"] =
        json!(["label"]);
    without_secret["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] =
        json!(["label"]);
    let without_secret = compile_value(&without_secret).unwrap();
    let mut required_encrypted = encrypted_project();
    required_encrypted["recordTypes"][0]["fields"][1]["required"] = json!(true);
    let required_encrypted = compile_value(&required_encrypted).unwrap();
    let added_required = compiled_registry_change_set(&without_secret, &required_encrypted, prior);
    assert!(added_required.changes.iter().any(|change| {
        change.code == Code::FieldAddedRequired && change.class == Class::Unsupported
    }));
    assert!(
        compiled_registry_change_set(&encrypted_unique, &encrypted_unique, prior)
            .changes
            .is_empty()
    );
}
