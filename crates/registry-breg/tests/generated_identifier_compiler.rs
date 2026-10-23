// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, ConstraintSource};
use registry_breg::model::CompiledGeneratedIdentifierStrategy;
use registry_platform_canonical_json::parse_json_strict;
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "generated-identifiers",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://registry.example.test"
        },
        "datasets": [{"id": "records"}],
        "recordTypes": [{
            "id": "record",
            "primaryDataset": "records",
            "route": "records",
            "mutationMode": "mutable",
            "classification": "internal",
            "fields": [
                {
                    "id": "jurisdiction",
                    "type": "string",
                    "minimumLength": 2,
                    "maximumLength": 16,
                    "required": true,
                    "classification": "internal"
                },
                {
                    "id": "registration-code",
                    "apiName": "registrationCode",
                    "type": "string",
                    "minimumLength": 10,
                    "maximumLength": 24,
                    "classification": "public",
                    "generate": {
                        "type": "sequence",
                        "prefix": "REG-",
                        "minimumDigits": 6,
                        "scope": ["jurisdiction"]
                    }
                },
                {
                    "id": "public-token",
                    "apiName": "publicToken",
                    "type": "string",
                    "minimumLength": 10,
                    "maximumLength": 10,
                    "classification": "public",
                    "generate": {
                        "type": "random",
                        "prefix": "T-",
                        "length": 8
                    }
                }
            ]
        }],
        "accessProfiles": [{
            "id": "editor",
            "principalClaim": "registry_principal",
            "requiredScopes": "unrestricted",
            "permissions": {"records": [{
                "recordType": "record",
                "operations": ["create", "get"],
                "readableFields": ["jurisdiction", "registration-code", "public-token"],
                "writableFields": ["jurisdiction"],
                "rowBoundaries": "unrestricted"
            }]}
        }]
    })
}

fn compile(
    value: &Value,
) -> Result<registry_breg::CompiledRegistry, registry_breg::diagnostics::CompileFailure> {
    let bytes = serde_json::to_vec(value).expect("project serializes");
    let project = parse_project_json(&bytes)?;
    compile_project(&project, &[], CompileProfile::Authoring)
}

#[test]
fn generated_identifiers_compile_storage_authority_and_scoped_uniqueness() {
    let compiled = compile(&project_value()).expect("generated identifiers compile");
    let entity = &compiled.entities()["record"];

    let sequence = entity.fields["registration-code"]
        .generate
        .as_ref()
        .expect("sequence generation is compiled");
    assert_eq!(sequence.prefix, "REG-");
    assert_eq!(sequence.scope, vec!["jurisdiction".to_owned()]);
    assert!(matches!(
        &sequence.strategy,
        CompiledGeneratedIdentifierStrategy::Sequence { minimum_digits: 6 }
    ));
    assert!(entity.fields["registration-code"].required);

    let random = entity.fields["public-token"]
        .generate
        .as_ref()
        .expect("random generation is compiled");
    assert_eq!(random.prefix, "T-");
    assert!(random.scope.is_empty());
    assert!(matches!(
        &random.strategy,
        CompiledGeneratedIdentifierStrategy::Random { length: 8 }
    ));
    assert!(entity.fields["public-token"].required);

    assert!(matches!(
        &entity.constraints["generated:registration-code"],
        ConstraintSource::Unique { id: Some(id), fields, when: None }
            if id == "generated:registration-code"
                && fields == &["jurisdiction".to_owned(), "registration-code".to_owned()]
    ));
    assert!(matches!(
        &entity.constraints["generated:public-token"],
        ConstraintSource::Unique { fields, when: None, .. }
            if fields == &["public-token".to_owned()]
    ));

    let seed = compiled
        .ddl()
        .statements
        .iter()
        .find(|statement| {
            statement.id == "entity.record.field.registration-code.generated-identifiers.seed"
        })
        .expect("sequence seed statement is generated");
    assert!(seed.sql.contains("ltrim(suffix, '0')"));
    assert!(seed.sql.contains("char_length(canonical_digits) <= 19"));
    assert!(!seed.sql.contains("suffix::numeric"));
}

#[test]
fn generated_identifiers_are_read_only_in_generated_contracts() {
    let compiled = compile(&project_value()).expect("generated identifiers compile");
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    let input = &openapi["components"]["schemas"]["record-create-input"];
    assert_eq!(
        input["properties"],
        json!({
            "jurisdiction": {"type": "string", "minLength": 2, "maxLength": 16}
        })
    );
    assert_eq!(input["required"], json!(["jurisdiction"]));

    let schema = compiled
        .artifacts()
        .get("generated/schemas/record.schema.json")
        .expect("read schema is generated");
    let schema = parse_json_strict(&schema.bytes).expect("record schema is strict JSON");
    assert_eq!(schema["properties"]["registrationCode"]["readOnly"], true);
    assert_eq!(schema["properties"]["publicToken"]["readOnly"], true);
    assert_eq!(
        schema["required"],
        json!(["jurisdiction", "registrationCode", "publicToken"])
    );
}

#[test]
fn generated_identifier_semantics_are_strictly_validated() {
    let cases = [
        (
            "breg.field.generate-scope-field-optional",
            json!({
                "id": "code", "type": "string", "maximumLength": 32,
                "classification": "internal",
                "generate": {"type": "sequence", "minimumDigits": 4, "scope": ["optional-scope"]}
            }),
            json!({
                "id": "optional-scope", "type": "string", "maximumLength": 8,
                "classification": "internal"
            }),
        ),
        (
            "breg.field.generate-type-unsupported",
            json!({
                "id": "code", "type": "int64", "classification": "internal",
                "generate": {"type": "sequence", "minimumDigits": 4}
            }),
            json!({
                "id": "scope", "type": "string", "maximumLength": 8,
                "required": true, "classification": "internal"
            }),
        ),
    ];
    for (expected, generated, companion) in cases {
        let mut project = project_value();
        project["recordTypes"][0]["fields"] = json!([companion, generated]);
        project["accessProfiles"] = json!([]);
        let failure = compile(&project).expect_err(expected);
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == expected),
            "{expected}: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn generated_identifier_and_scope_have_an_index_safe_size_bound() {
    let mut project = project_value();
    project["recordTypes"][0]["fields"][0]["maximumLength"] = json!(232);
    compile(&project).expect("the combined field and scope fit the index budget");

    project["recordTypes"][0]["fields"][0]["maximumLength"] = json!(233);
    let failure = compile(&project).expect_err("an oversized scope is refused at compilation");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "breg.field.generate-index-key-too-large" }));

    let mut project = project_value();
    project["recordTypes"][0]["fields"][1]["generate"]["scope"] = json!([]);
    project["recordTypes"][0]["fields"][1]["maximumLength"] = json!(257);
    let failure = compile(&project).expect_err("an oversized retained identifier field is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "breg.field.generate-index-key-too-large" }));

    let mut project = project_value();
    project["recordTypes"][0]["fields"][0]["maximumLength"] = json!(116);
    project["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "district", "type": "text", "maximumLength": 117,
            "required": true, "classification": "internal"
        }));
    project["recordTypes"][0]["fields"][1]["generate"]["scope"] =
        json!(["jurisdiction", "district"]);
    let failure = compile(&project).expect_err("aggregate scope size is bounded");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "breg.field.generate-index-key-too-large" }));
}

#[test]
fn generated_identifier_reader_refuses_unknown_and_duplicate_members() {
    let mut unknown = project_value();
    unknown["recordTypes"][0]["fields"][1]["generate"]["minimumLength"] = json!(6);
    let failure = compile(&unknown).expect_err("unknown generation member is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.unknown-key"));

    let source = serde_json::to_vec(&project_value()).expect("project serializes");
    let text = String::from_utf8(source).expect("project JSON is UTF-8");
    let duplicate = text.replace(
        "\"scope\":[\"jurisdiction\"]",
        "\"scope\":[\"jurisdiction\",\"jurisdiction\"]",
    );
    let failure = parse_project_json(duplicate.as_bytes()).expect_err("duplicate scope is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.duplicate-item"));
}

#[test]
fn random_generation_takes_no_alphabet_or_scope() {
    for (member, value) in [
        ("alphabet", json!("ABCDEFGH")),
        ("scope", json!(["jurisdiction"])),
    ] {
        let mut project = project_value();
        project["recordTypes"][0]["fields"][2]["generate"][member] = value;
        let failure = compile(&project).expect_err(member);
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "config.unknown-key"),
            "{member}: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn length_diagnostics_state_the_field_bounds_each_strategy_needs() {
    // "REG-" plus max(6, 19) digits needs 23 characters; "T-" plus 8 is 10.
    let mut sequence = project_value();
    sequence["recordTypes"][0]["fields"][1]["maximumLength"] = json!(12);
    let mut random = project_value();
    random["recordTypes"][0]["fields"][2]["minimumLength"] = json!(9);
    random["recordTypes"][0]["fields"][2]["maximumLength"] = json!(9);
    for (case, project, expected) in [
        (
            "sequence",
            sequence,
            ["max(minimumDigits, 19)", "maximumLength at least 23"],
        ),
        (
            "random",
            random,
            ["exactly 10 characters", "maximumLength at least 10"],
        ),
    ] {
        let failure = compile(&project).expect_err(case);
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.field.generate-length-outside-field")
            .unwrap_or_else(|| panic!("{case}: {:?}", failure.diagnostics()));
        for fragment in expected {
            assert!(
                diagnostic.message.contains(fragment),
                "{case}: {}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn sequence_scope_fields_cannot_hold_restricted_values_or_references() {
    // The reservation ledger keeps scope values after record erasure.
    let mut restricted = project_value();
    restricted["recordTypes"][0]["fields"][0]["classification"] = json!("restricted");
    let mut reference = project_value();
    reference["recordTypes"][0]["fields"][0] = json!({
        "id": "jurisdiction", "type": "reference", "target": "record",
        "required": true, "classification": "internal"
    });
    for (case, project) in [("restricted", restricted), ("reference", reference)] {
        let failure = compile(&project).expect_err(case);
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "breg.field.generate-scope-field-sensitive"),
            "{case}: {:?}",
            failure.diagnostics()
        );
    }

    let mut public = project_value();
    public["recordTypes"][0]["fields"][0]["classification"] = json!("public");
    compile(&public).expect("a public scope field compiles");
}

#[test]
fn generated_fields_cannot_be_classified_above_internal() {
    // The migration seed copies retained values into the reservation ledger,
    // which keeps them after record erasure.
    for (case, field) in [(0usize, "registration-code"), (1, "public-token")] {
        let mut project = project_value();
        project["recordTypes"][0]["fields"][case + 1]["classification"] = json!("restricted");
        let failure = compile(&project).expect_err(field);
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "breg.field.generate-classification-sensitive"),
            "{field}: {:?}",
            failure.diagnostics()
        );
    }

    let mut internal = project_value();
    internal["recordTypes"][0]["fields"][1]["classification"] = json!("internal");
    compile(&internal).expect("an internal generated field compiles");
}

#[test]
fn generated_identifiers_cannot_be_caller_writable() {
    let mut project = project_value();
    project["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] =
        json!(["jurisdiction", "registration-code"]);
    let failure = compile(&project).expect_err("generated identifier write grant is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "breg.access-profile.generated-field-writable" }));
}

#[test]
fn fixed_actions_cannot_supply_server_generated_identifiers() {
    let mut project = project_value();
    project["actions"] = json!([{
        "id": "create-record",
        "execution": {"mode": "immediate"},
        "inputs": [],
        "plan": {"type": "fixed", "effects": [{
            "id": "record",
            "target": {"recordType": "record"},
            "operation": "create",
            "set": {
                "jurisdiction": {"value": "TH"},
                "registration-code": {"value": "REG-000001"}
            }
        }]}
    }]);
    project["accessProfiles"] = json!([{
        "id": "operator",
        "default": true,
        "principalClaim": "registry_principal",
        "requiredScopes": "unrestricted",
        "permissions": {"actions": [{
            "action": "create-record",
            "operations": ["invoke"],
            "targets": [{"recordType": "record", "rowBoundaries": "unrestricted"}]
        }]}
    }]);

    let failure = compile(&project).expect_err("Action cannot set a generated identifier");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.effect-field-generated"));
}

#[test]
fn create_effect_bounds_include_server_generated_fields() {
    for (mode, operation) in [("immediate", "invoke"), ("proposal", "start")] {
        let mut project = project_value();
        let mut fields = Vec::new();
        let mut set = serde_json::Map::new();
        for index in 0..128 {
            let id = format!("authored-{index}");
            fields.push(json!({
                "id": id,
                "type": "string",
                "maximumLength": 1,
                "required": true,
                "classification": "internal"
            }));
            set.insert(id, json!({"value": "x"}));
        }
        fields.push(json!({
            "id": "generated",
            "type": "string",
            "maximumLength": 19,
            "classification": "internal",
            "generate": {"type": "sequence", "minimumDigits": 1}
        }));
        project["recordTypes"][0]["fields"] = Value::Array(fields);

        let execution = if mode == "proposal" {
            json!({
                "mode": "proposal",
                "proposal": {
                    "review": {"type": "none"},
                    "application": {"mode": "manual"},
                    "retention": {"mode": "retain"}
                }
            })
        } else {
            json!({"mode": "immediate"})
        };
        project["actions"] = json!([{
            "id": "create-record",
            "execution": execution,
            "inputs": [{
                "id": "request-note",
                "type": "string",
                "maximumLength": 1,
                "classification": "internal"
            }],
            "plan": {"type": "fixed", "effects": [{
                "id": "record",
                "target": {"recordType": "record"},
                "operation": "create",
                "set": Value::Object(set)
            }]}
        }]);
        project["accessProfiles"] = json!([{
            "id": "operator",
            "default": true,
            "principalClaim": "registry_principal",
            "requiredScopes": "unrestricted",
            "permissions": {"actions": [{
                "action": "create-record",
                "operations": [operation],
                "targets": [{"recordType": "record", "rowBoundaries": "unrestricted"}]
            }]}
        }]);

        let failure = compile(&project).expect_err("generated field exceeds create context bound");
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "breg.action.bounds-field-mutations"),
            "{mode}: {:?}",
            failure.diagnostics()
        );
    }
}
