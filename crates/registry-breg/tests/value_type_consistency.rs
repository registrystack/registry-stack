// SPDX-License-Identifier: Apache-2.0

use registry_breg::{
    compiler::{compile_project, CompileProfile},
    contract::{
        read_module_yaml, read_project_yaml, FieldTypeSource, RegistryModule, RegistryProject,
    },
};
use serde_json::{json, Value};

#[cfg(feature = "schema")]
use registry_breg::schema::{documents, REGISTRY_MODULE_SCHEMA_FILE, REGISTRY_PROJECT_SCHEMA_FILE};

const SCALAR_REQUIRED: &str = "breg.value-type.scalar-required";
type ReadDiagnostics = fn(&str, &[u8]) -> Vec<registry_platform_yaml::Diagnostic>;

fn project_source(definition: Value, use_site: &str) -> Value {
    let mut fields = Vec::new();
    let mut inputs = Vec::new();
    let uses_action = matches!(use_site, "action" | "both");
    match use_site {
        "field" => fields.push(json!({
            "id": "value",
            "typeRef": "shared-value",
            "classification": "internal"
        })),
        "action" => inputs.push(json!({
            "id": "value",
            "typeRef": "shared-value",
            "classification": "internal"
        })),
        "both" => {
            fields.push(json!({
                "id": "value",
                "typeRef": "shared-value",
                "classification": "internal"
            }));
            inputs.push(json!({
                "id": "value",
                "typeRef": "shared-value",
                "classification": "internal"
            }));
        }
        "unused" => {}
        other => panic!("unknown use site {other}"),
    }
    let actions = if uses_action {
        json!([{
            "id": "set-value",
            "execution": {"mode": "immediate"},
            "inputs": inputs,
            "plan": {"type": "fixed", "effects": [{
                "id": "entry",
                "target": {"recordType": "entry"},
                "operation": "create",
                "set": {"value": {"fromInput": "value"}}
            }]}
        }])
    } else {
        json!([])
    };
    let access_profiles = if uses_action {
        json!([{
            "id": "operator",
            "default": true,
            "principalClaim": "principal",
            "requiredScopes": "unrestricted",
            "permissions": {"actions": [{
                "action": "set-value",
                "operations": ["invoke"],
                "targets": [{"recordType": "entry", "rowBoundaries": "unrestricted"}],
                "results": ["entry"]
            }]}
        }])
    } else {
        json!([])
    };
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "value-type-consistency",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://authoring.example.test/value-type-consistency"
        },
        "datasets": [{"id": "records"}],
        "valueTypes": {"shared-value": definition},
        "recordTypes": [{
            "id": "entry",
            "primaryDataset": "records",
            "route": "entries",
            "mutationMode": "mutable",
            "fields": fields
        }],
        "actions": actions,
        "accessProfiles": access_profiles
    })
}

fn module_source(definition: Value, use_site: &str) -> Value {
    let mut source = project_source(definition, use_site);
    source["apiVersion"] = json!("id.registrystack.org/formats/breg/module/v1alpha1");
    source["kind"] = json!("BRegModule");
    source["id"] = json!("definitions");
    source["version"] = json!("1");
    source.as_object_mut().unwrap().remove("project");
    source.as_object_mut().unwrap().remove("datasets");
    source.as_object_mut().unwrap().remove("accessProfiles");
    source
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test source serializes")
}

fn assert_string(field_type: &FieldTypeSource) {
    assert!(matches!(
        field_type,
        FieldTypeSource::String {
            min_length: 2,
            max_length: 24
        }
    ));
}

#[test]
fn scalar_value_types_resolve_for_record_fields_and_action_inputs_in_both_formats() {
    let definition = json!({
        "type": "string",
        "minimumLength": 2,
        "maximumLength": 24
    });

    let project = read_project_yaml(
        "registry.yaml",
        &bytes(&project_source(definition.clone(), "both")),
    )
    .expect("a project scalar alias is valid")
    .value;
    assert_string(&project.entities[0].fields[0].field_type);
    assert_string(&project.actions[0].inputs[0].field_type);
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("a project scalar alias compiles at both use sites");

    let module = read_module_yaml("module.yaml", &bytes(&module_source(definition, "both")))
        .expect("a module scalar alias is valid")
        .value;
    assert_string(&module.entities[0].fields[0].field_type);
    assert_string(&module.actions[0].inputs[0].field_type);
    compile_project(&module_host(true), &[module], CompileProfile::Authoring)
        .expect("a module scalar alias compiles at both use sites");
}

#[test]
fn malformed_value_types_are_refused_at_the_declaration_in_both_formats() {
    let definition = json!({"type": "string", "maximumLength": 0});
    for (file, source, read) in [
        (
            "registry.yaml",
            project_source(definition.clone(), "both"),
            read_project_diagnostics as ReadDiagnostics,
        ),
        (
            "module.yaml",
            module_source(definition, "both"),
            read_module_diagnostics as ReadDiagnostics,
        ),
    ] {
        let diagnostics = read(file, &bytes(&source));
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.out-of-range")
            .unwrap_or_else(|| panic!("missing bound diagnostic in {file}: {diagnostics:?}"));
        assert_eq!(diagnostic.path, "/valueTypes/shared-value/maximumLength");
    }
}

fn read_project_diagnostics(file: &str, source: &[u8]) -> Vec<registry_platform_yaml::Diagnostic> {
    read_project_yaml(file, source)
        .expect_err("the malformed project declaration is refused")
        .diagnostics()
        .to_vec()
}

fn read_module_diagnostics(file: &str, source: &[u8]) -> Vec<registry_platform_yaml::Diagnostic> {
    read_module_yaml(file, source)
        .expect_err("the malformed module declaration is refused")
        .diagnostics()
        .to_vec()
}

#[test]
fn compound_value_types_are_refused_at_each_authored_declaration() {
    let cases = [
        ("reference", json!({"type": "reference", "target": "entry"})),
        (
            "crs84-point",
            json!({"type": "crs84-point", "precision": 4}),
        ),
        (
            "structured",
            json!({
                "type": "structured",
                "maximumBytes": 256,
                "schema": {"type": "object", "additionalProperties": false}
            }),
        ),
    ];

    for (kind, definition) in cases {
        for use_site in ["field", "action", "unused"] {
            let project = read_project_yaml(
                "registry.yaml",
                &bytes(&project_source(definition.clone(), use_site)),
            )
            .expect_err("a project compound value type is refused");
            assert_scalar_required(project.diagnostics(), "project", kind, use_site);

            let module = read_module_yaml(
                "module.yaml",
                &bytes(&module_source(definition.clone(), use_site)),
            )
            .expect_err("a module compound value type is refused");
            assert_scalar_required(module.diagnostics(), "module", kind, use_site);
        }
    }
}

fn assert_scalar_required(
    diagnostics: &[registry_platform_yaml::Diagnostic],
    format: &str,
    kind: &str,
    use_site: &str,
) {
    let diagnostic = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == SCALAR_REQUIRED)
        .unwrap_or_else(|| {
            panic!("missing scalar-only refusal for {format} {kind} at {use_site}: {diagnostics:?}")
        });
    assert_eq!(diagnostic.path, "/valueTypes/shared-value");
    assert!(
        diagnostic.message.contains("scalar"),
        "{format} {kind} at {use_site}: {diagnostic:?}"
    );
    assert!(
        diagnostic.suggested_action.contains("directly"),
        "{format} {kind} at {use_site}: {diagnostic:?}"
    );
}

#[test]
fn unknown_value_type_uses_name_the_record_field_or_action_input_in_both_formats() {
    let scalar = json!({"type": "string", "maximumLength": 24});
    for (use_site, path) in [
        ("field", "/recordTypes/0/fields/0/typeRef"),
        ("action", "/actions/0/inputs/0/typeRef"),
    ] {
        let mut project = project_source(scalar.clone(), use_site);
        set_type_reference(&mut project, use_site, "missing-value");
        let report = read_project_yaml("registry.yaml", &bytes(&project))
            .expect_err("an unknown project value type reference is refused");
        assert_reference_diagnostic(report.diagnostics(), path);

        let mut module = module_source(scalar.clone(), use_site);
        set_type_reference(&mut module, use_site, "missing-value");
        let report = read_module_yaml("module.yaml", &bytes(&module))
            .expect_err("an unknown module value type reference is refused");
        assert_reference_diagnostic(report.diagnostics(), path);
    }
}

fn set_type_reference(source: &mut Value, use_site: &str, reference: &str) {
    let field = if use_site == "field" {
        &mut source["recordTypes"][0]["fields"][0]
    } else {
        &mut source["actions"][0]["inputs"][0]
    };
    field["typeRef"] = json!(reference);
}

fn assert_reference_diagnostic(diagnostics: &[registry_platform_yaml::Diagnostic], path: &str) {
    let diagnostic = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.value-type.reference-invalid")
        .unwrap_or_else(|| panic!("missing value-type reference diagnostic: {diagnostics:?}"));
    assert_eq!(diagnostic.path, path);
    assert!(diagnostic.suggested_action.contains("declared value type"));
}

#[test]
fn programmatic_compilation_checks_unused_module_value_types_like_project_value_types() {
    let scalar = json!({"type": "string", "maximumLength": 24});
    let mut project = read_project_yaml(
        "registry.yaml",
        &bytes(&project_source(scalar.clone(), "unused")),
    )
    .expect("the scalar project declaration parses")
    .value;
    project.value_types.insert(
        "shared-value".to_owned(),
        FieldTypeSource::Structured {
            max_bytes: 256,
            schema: json!({"type": "object", "additionalProperties": false}),
        },
    );
    assert_compile_scalar_required(&project, &[], "project valueTypes");

    let mut module = read_module_yaml("module.yaml", &bytes(&module_source(scalar, "unused")))
        .expect("the scalar module declaration parses")
        .value;
    module.value_types.insert(
        "shared-value".to_owned(),
        FieldTypeSource::Structured {
            max_bytes: 256,
            schema: json!({"type": "object", "additionalProperties": false}),
        },
    );
    let host = module_host(false);
    assert_compile_scalar_required(&host, &[module], "module valueTypes");
}

fn module_host(with_action_permission: bool) -> RegistryProject {
    let mut source = json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "module-host",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://authoring.example.test/module-host"
        },
        "datasets": [{"id": "records"}],
        "modules": [{"id": "definitions", "version": "1"}]
    });
    if with_action_permission {
        source["accessProfiles"] = json!([{
            "id": "operator",
            "default": true,
            "principalClaim": "principal",
            "requiredScopes": "unrestricted",
            "permissions": {"actions": [{
                "action": "set-value",
                "operations": ["invoke"],
                "targets": [{"recordType": "entry", "rowBoundaries": "unrestricted"}],
                "results": ["entry"]
            }]}
        }]);
    }
    read_project_yaml("registry.yaml", &bytes(&source))
        .expect("the module host parses")
        .value
}

fn assert_compile_scalar_required(
    project: &RegistryProject,
    modules: &[RegistryModule],
    label: &str,
) {
    let failure = match compile_project(project, modules, CompileProfile::Authoring) {
        Ok(_) => panic!("{label} accepted a structured reusable type"),
        Err(failure) => failure,
    };
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == SCALAR_REQUIRED),
        "missing scalar-only refusal for {label}: {:?}",
        failure.diagnostics()
    );
}

#[cfg(feature = "schema")]
#[test]
fn authoring_schemas_expose_scalar_aliases_without_hiding_direct_compound_fields() {
    let documents = documents().expect("authoring schemas generate");
    let mut field_type_schema = <FieldTypeSource as schemars::JsonSchema>::json_schema(
        &mut schemars::SchemaGenerator::default(),
    )
    .to_value();
    registry_breg::schema::refuse_null(&mut field_type_schema, "");
    let direct_type_branches = field_type_schema["oneOf"]
        .as_array()
        .expect("field types are a tagged union");
    let scalar_branches = direct_type_branches
        .iter()
        .filter(|branch| {
            !matches!(
                branch
                    .pointer("/properties/type/const")
                    .and_then(Value::as_str),
                Some("reference" | "crs84-point" | "structured")
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    for (schema_file, source) in [
        (
            REGISTRY_PROJECT_SCHEMA_FILE,
            project_source(json!({"type": "string", "maximumLength": 24}), "both"),
        ),
        (
            REGISTRY_MODULE_SCHEMA_FILE,
            module_source(json!({"type": "string", "maximumLength": 24}), "both"),
        ),
    ] {
        let schema_document: Value = serde_json::from_str(&documents[schema_file])
            .expect("generated authoring schema is JSON");
        let direct_field_branches = schema_document["$defs"]["FieldSource"]["anyOf"]
            .as_array()
            .expect("direct fields are a union");
        assert_eq!(
            schema_document["$defs"]["ReusableValueTypeSource"]["oneOf"],
            json!(scalar_branches.clone()),
            "{schema_file} reuses the scalar branches of the direct field schema"
        );
        for compound_definition in [
            "ReferenceFieldSourceSchema",
            "Crs84PointFieldSourceSchema",
            "StructuredFieldSourceSchema",
        ] {
            assert!(
                direct_field_branches.iter().any(|branch| {
                    branch
                        .get("$ref")
                        .and_then(Value::as_str)
                        .is_some_and(|reference| reference.ends_with(compound_definition))
                }),
                "{schema_file} retains direct {compound_definition} fields"
            );
        }
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema_document)
            .expect("generated authoring schema compiles");
        assert!(
            schema.is_valid(&source),
            "{schema_file} accepts scalar aliases"
        );

        let mut aliased_compound = source.clone();
        aliased_compound["valueTypes"]["shared-value"] = json!({
            "type": "structured",
            "maximumBytes": 256,
            "schema": {"type": "object", "additionalProperties": false}
        });
        assert!(
            !schema.is_valid(&aliased_compound),
            "{schema_file} refuses reusable compound aliases"
        );

        for use_site in ["field", "action"] {
            let mut direct_compound = if schema_file == REGISTRY_MODULE_SCHEMA_FILE {
                module_source(json!({"type": "string", "maximumLength": 24}), use_site)
            } else {
                project_source(json!({"type": "string", "maximumLength": 24}), use_site)
            };
            direct_compound
                .as_object_mut()
                .unwrap()
                .remove("valueTypes");
            let declaration = json!({
                "id": "value",
                "type": "structured",
                "maximumBytes": 256,
                "schema": {"type": "object", "additionalProperties": false},
                "classification": "internal"
            });
            if use_site == "field" {
                direct_compound["recordTypes"][0]["fields"][0] = declaration;
            } else {
                direct_compound["actions"][0]["inputs"][0] = declaration;
            }
            assert!(
                schema.is_valid(&direct_compound),
                "{schema_file} keeps direct compound {use_site} declarations"
            );
        }
    }
}
