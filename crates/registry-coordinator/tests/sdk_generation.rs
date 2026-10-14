// SPDX-License-Identifier: Apache-2.0
use registry_coordinator::{
    definition::Definition,
    sdk::{generate, Language},
};

fn fixture() -> (tempfile::TempDir, Definition) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("workflow.yaml"),
        r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: sdk-fixture, version: "1"}
workflow:
  input:
    type: object
    additionalProperties: false
    required: [name]
    properties:
      name: {type: string}
      channel: {enum: [email, sms]}
      tags: {type: array, items: {type: string}}
  deadlineSeconds: 60
  start: done
  steps:
    done:
      type: finish
      outcome: accepted
      output: {type: input, path: /name}
  outcomes:
    accepted: {type: string}
"#,
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    (root, definition)
}

#[test]
fn exported_clients_pin_the_compiled_revision_and_use_maintained_clients() {
    let (_root, definition) = fixture();
    let typescript = generate(&definition, Language::Typescript).unwrap();
    let python = generate(&definition, Language::Python).unwrap();
    for source in [&typescript, &python] {
        assert!(source.contains(&definition.digest));
        assert!(source.contains("sdk-fixture"));
        assert!(source.contains("accepted"));
        assert!(source.contains("Workflow contract mismatch"));
        assert!(!source.contains("/v1/"));
        assert!(!source.contains("fetch("));
        assert!(!source.contains("httpx"));
    }
    assert!(typescript.contains("\"name\": string"));
    assert!(typescript.contains("\"channel\"?: \"email\" | \"sms\""));
    assert!(typescript.contains("client.start(token, idempotencyKey"));
    assert!(typescript.contains("client.status(token, runId)"));
    assert!(typescript.contains("checked(run.status);"));
    assert!(python.contains("\"name\": Required[str]"));
    assert!(python.contains("Literal[\"email\", \"sms\"]"));
    assert!(python.contains("client.start(token, idempotency_key"));
    assert!(python.contains("_checked(run[\"status\"])"));
    assert_eq!(
        typescript,
        generate(&definition, Language::Typescript).unwrap()
    );
    assert_eq!(python, generate(&definition, Language::Python).unwrap());
}

#[test]
fn python_null_outcome_types_are_executable() {
    let (root, _) = fixture();
    let path = root.path().join("workflow.yaml");
    let source = std::fs::read_to_string(&path)
        .unwrap()
        .replace("      output: {type: input, path: /name}\n", "")
        .replace(
            "accepted: {type: string}",
            "accepted: {anyOf: [{type: 'null'}, {type: 'null'}]}",
        );
    std::fs::write(&path, source).unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let source = generate(&definition, Language::Python).unwrap();
    assert!(!source.contains("None | None"));
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn schema_fixture(schema: serde_json::Value) -> (tempfile::TempDir, Definition) {
    let root = tempfile::tempdir().unwrap();
    let project = serde_json::json!({
        "apiVersion":registry_coordinator::authoring::API_VERSION, "kind":"CoordinatorProject",
        "project":{"id":"schema-sdk","version":"1"},
        "workflow":{"input":schema,"deadlineSeconds":60,"start":"done",
            "steps":{"done":{"type":"finish","outcome":"accepted"}},
            "outcomes":{"accepted":{"type":"null"}}}
    });
    std::fs::write(root.path().join("workflow.yaml"), project.to_string()).unwrap();
    let definition = Definition::load(root.path()).unwrap();
    (root, definition)
}

#[test]
fn mixed_named_and_typed_additional_members_refuse_both_exports() {
    let (_root, definition) = schema_fixture(serde_json::json!({
        "type":"object", "properties":{"known":{"type":"string"}},
        "additionalProperties":{"type":"integer"}
    }));
    let validator = jsonschema::JSONSchema::compile(&definition.workflow.input).unwrap();
    assert!(validator.is_valid(&serde_json::json!({"extra":7})));
    assert!(!validator.is_valid(&serde_json::json!({"extra":"wrong"})));
    for language in [Language::Typescript, Language::Python] {
        let error = generate(&definition, language).unwrap_err();
        assert_eq!(error.code, "workflow.types-refused");
        assert!(error.message.contains("open object with named members"));
    }
    let (_root, dictionary) = schema_fixture(serde_json::json!({
        "type":"object", "additionalProperties":{"type":"integer"}
    }));
    assert!(generate(&dictionary, Language::Typescript)
        .unwrap()
        .contains("export type Input = Record<string, number>"));
    assert!(generate(&dictionary, Language::Python)
        .unwrap()
        .contains("Input: TypeAlias = dict[str, int]"));
}

fn assert_open_named_object_refuses_both_exports(schema: serde_json::Value) {
    let (_root, definition) = schema_fixture(schema);
    let validator = jsonschema::JSONSchema::compile(&definition.workflow.input).unwrap();
    assert!(validator.is_valid(&serde_json::json!({"known":"valid", "extra":{"nested":true}})));
    for language in [Language::Typescript, Language::Python] {
        let error = generate(&definition, language).unwrap_err();
        assert_eq!(error.code, "workflow.types-refused");
        assert!(error.message.contains("open object with named members"));
    }
}

#[test]
fn explicit_untyped_additional_members_refuse_both_exports() {
    assert_open_named_object_refuses_both_exports(serde_json::json!({
        "type":"object", "properties":{"known":{"type":"string"}},
        "additionalProperties":true
    }));
}

#[test]
fn omitted_additional_members_refuse_both_exports() {
    assert_open_named_object_refuses_both_exports(serde_json::json!({
        "type":"object", "properties":{"known":{"type":"string"}}
    }));
}

#[test]
fn a_closed_empty_object_is_not_an_unconstrained_typescript_value() {
    let (_root, definition) = schema_fixture(serde_json::json!({
        "type":"object", "additionalProperties":false
    }));
    let typescript = generate(&definition, Language::Typescript).unwrap();
    assert!(typescript.contains("export type Input = Record<string, never>;"));
}

#[test]
#[ignore = "requires COORDINATOR_SDK_TSC pointing to the installed TypeScript compiler"]
fn typescript_closed_empty_object_rejects_primitives_and_members() {
    let (root, definition) = schema_fixture(serde_json::json!({
        "type":"object", "additionalProperties":false
    }));
    let source = generate(&definition, Language::Typescript).unwrap();
    let input = source
        .lines()
        .find(|line| line.starts_with("export type Input ="))
        .unwrap();
    std::fs::write(root.path().join("check.ts"), format!(
        "{input}\nconst valid: Input = {{}};\n// @ts-expect-error A closed object cannot hold a primitive.\nconst number: Input = 123;\n// @ts-expect-error A closed object cannot hold a string.\nconst text: Input = 'wrong';\n// @ts-expect-error The object declares no members.\nconst member: Input = {{ extra: true }};\n"
    )).unwrap();
    let compiler = std::env::var("COORDINATOR_SDK_TSC").expect("installed TypeScript compiler");
    let checked = std::process::Command::new(compiler)
        .args(["--strict", "--noEmit", "--skipLibCheck", "false"])
        .arg(root.path().join("check.ts"))
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
}

#[test]
fn intersections_group_typescript_operands_and_refuse_lossy_python_export() {
    let (_root, definition) = schema_fixture(serde_json::json!({"allOf":[
        {"anyOf":[{"type":"string"},{"type":"number"}]}, {"const":123}
    ]}));
    let typescript = generate(&definition, Language::Typescript).unwrap();
    assert!(typescript.contains("export type Input = (string | number) & (123);"));
    let error = generate(&definition, Language::Python).unwrap_err();
    assert_eq!(error.code, "workflow.types-refused");
    assert!(error.message.contains("schema intersection"));
}

#[test]
#[ignore = "requires COORDINATOR_SDK_TSC pointing to the installed TypeScript compiler"]
fn typescript_intersection_rejects_invalid_union_members() {
    let (root, definition) = schema_fixture(serde_json::json!({"allOf":[
        {"anyOf":[{"type":"string"},{"type":"number"}]}, {"const":123}
    ]}));
    let source = generate(&definition, Language::Typescript).unwrap();
    let input = source
        .lines()
        .find(|line| line.starts_with("export type Input ="))
        .unwrap();
    std::fs::write(root.path().join("check.ts"), format!(
        "{input}\nconst valid: Input = 123;\n// @ts-expect-error An invalid union member cannot satisfy the intersection.\nconst invalid: Input = 'wrong';\n// @ts-expect-error The constant operand remains binding.\nconst wrongNumber: Input = 124;\n"
    )).unwrap();
    let compiler = std::env::var("COORDINATOR_SDK_TSC").expect("installed TypeScript compiler");
    let checked = std::process::Command::new(compiler)
        .args(["--strict", "--noEmit", "--skipLibCheck", "false"])
        .arg(root.path().join("check.ts"))
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
}
