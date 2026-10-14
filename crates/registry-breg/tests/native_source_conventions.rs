// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "schema")]
use registry_breg::contract::read_module_yaml;
use registry_breg::contract::read_project_yaml;
use serde_json::{json, Value};

fn facility() -> Value {
    registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../products/breg/examples/facility/registry.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn bytes(source: &Value) -> Vec<u8> {
    serde_norway::to_string(source).unwrap().into_bytes()
}

fn refusal(source: &Value, path: &str, code: &str) {
    let yaml = bytes(source);
    let report = read_project_yaml("registry.yaml", &yaml).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path == path && diagnostic.code == code)
        .unwrap_or_else(|| panic!("expected {code} at {path}: {}", report.render_human()));
    let site = diagnostic.source.as_ref().expect("a located refusal");
    assert!(site.line.is_some_and(|line| line > 1));
    assert!(site.column.is_some_and(|column| column > 0));
    if code == "config.unknown-key" {
        let text = std::str::from_utf8(&yaml).unwrap();
        let expected_line = text
            .lines()
            .position(|line| line.trim_start().starts_with("unexpectedMember:"))
            .unwrap()
            + 1;
        assert_eq!(site.line, Some(expected_line));
        let expected_column = text
            .lines()
            .nth(expected_line - 1)
            .unwrap()
            .find("unexpectedMember:")
            .unwrap()
            + 1;
        assert_eq!(site.column, Some(expected_column));
    }
}

#[test]
fn locally_defined_ids_and_type_keys_are_refused_at_their_source() {
    for path in [
        "/datasets/0/id",
        "/functions/0/id",
        "/reviewAuthorities/0/id",
        "/actions/1/execution/proposal/reviewContext/id",
    ] {
        let mut source = facility();
        *source.pointer_mut(path).unwrap() = json!("Bad Local ID");
        refusal(&source, path, "config.invalid-value");
    }
    let mut source = facility();
    source["valueTypes"]["Bad Type"] = json!({"type":"string","maximumLength":10});
    refusal(&source, "/valueTypes/Bad Type", "config.invalid-value");
}

#[test]
fn function_and_bound_plan_capability_duplicates_are_not_collapsed() {
    for path in ["/functions/0/capabilities", "/actions/1/plan/capabilities"] {
        let mut source = facility();
        let parent = path.rsplit_once('/').unwrap().0;
        source.pointer_mut(parent).unwrap()["capabilities"] = json!(["evidence", "evidence"]);
        refusal(&source, &format!("{path}/1"), "config.duplicate-item");
        let yaml = bytes(&source);
        let text = std::str::from_utf8(&yaml).unwrap();
        let occurrences: Vec<_> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| line.trim() == "- evidence")
            .collect();
        assert_eq!(occurrences.len(), 2);
        let report = read_project_yaml("registry.yaml", &yaml).unwrap_err();
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.related[0].path, format!("{path}/0"));
        assert_eq!(diagnostic.related[0].file, "registry.yaml");
        assert_eq!(diagnostic.related[0].line, Some(occurrences[0].0 + 1));
        assert_eq!(
            diagnostic.related[0].column,
            Some(occurrences[0].1.find("evidence").unwrap() + 1)
        );
        let site = diagnostic.source.as_ref().unwrap();
        assert_eq!(site.line, Some(occurrences[1].0 + 1));
        assert_eq!(
            site.column,
            Some(occurrences[1].1.find("evidence").unwrap() + 1)
        );
    }
}

#[test]
fn nested_union_refusals_keep_the_member_path_line_and_column() {
    for path in [
        "/functions/0",
        "/actions/0/execution",
        "/actions/1/plan",
        "/actions/2/execution/proposal/review",
        "/actions/2/execution/proposal/application",
    ] {
        let mut source = facility();
        source.pointer_mut(path).unwrap()["unexpectedMember"] = json!(true);
        refusal(
            &source,
            &format!("{path}/unexpectedMember"),
            "config.unknown-key",
        );
    }
}

#[test]
fn named_type_options_use_the_same_closed_typed_reader_as_inline_fields() {
    let mut source = facility();
    source["valueTypes"]["city"]["unexpectedMember"] = json!(true);
    refusal(
        &source,
        "/valueTypes/city/unexpectedMember",
        "config.unknown-key",
    );
    source = facility();
    source["valueTypes"]["unused-type"] = json!({"type":"boolean","unexpectedMember":true});
    refusal(
        &source,
        "/valueTypes/unused-type/unexpectedMember",
        "config.unknown-key",
    );
    source["valueTypes"]["unused-type"] = json!({"type":"string","maximumLength":0});
    refusal(
        &source,
        "/valueTypes/unused-type/maximumLength",
        "config.out-of-range",
    );
}

#[test]
fn resource_bounds_and_signed_comparison_thresholds_have_distinct_semantics() {
    for (key, values) in [
        ("maximumOperations", vec![0, 100_001]),
        ("maximumOutputBytes", vec![0, 2_097_153]),
    ] {
        for value in values {
            let mut source = facility();
            source["functions"][0]["limits"] = json!({key:value});
            refusal(
                &source,
                &format!("/functions/0/limits/{key}"),
                "config.out-of-range",
            );
        }
    }
    for value in [0, 33] {
        let mut source = facility();
        source["actions"][1]["execution"]["proposal"]["application"] =
            json!({"mode":"automatic","maximumAttempts":value});
        refusal(
            &source,
            "/actions/1/execution/proposal/application/maximumAttempts",
            "config.out-of-range",
        );
    }
    let mut source = facility();
    source["actions"][1]["commitGuards"]["targets"] = json!([
        {"input":"facility","field":"signed-value","atLeast":i64::MIN},
        {"input":"facility","field":"signed-value","atMost":i64::MAX}
    ]);
    read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
}

#[test]
fn review_policy_ids_are_external_and_keep_the_review_protocol_bound() {
    let mut source = facility();
    source["actions"][1]["execution"]["proposal"]["review"]["policy"]["id"] =
        json!("urn:example:Policy/Review@2");
    let read = read_project_yaml("registry.yaml", &bytes(&source))
        .unwrap()
        .value;
    assert!(serde_json::to_value(read)
        .unwrap()
        .to_string()
        .contains("urn:example:Policy/Review@2"));
    for id in [" ".to_owned(), "é".repeat(65)] {
        source["actions"][1]["execution"]["proposal"]["review"]["policy"]["id"] = json!(id);
        refusal(
            &source,
            "/actions/1/execution/proposal/review/policy/id",
            "config.invalid-value",
        );
    }
}

#[cfg(feature = "schema")]
#[test]
fn schema_and_reader_agree_on_bounds_native_tags_and_public_context_names() {
    let documents = registry_breg::schema::documents().unwrap();
    let document: Value =
        serde_json::from_str(&documents[registry_breg::schema::REGISTRY_PROJECT_SCHEMA_FILE])
            .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&document)
        .unwrap();
    let mut source = facility();
    assert!(schema.is_valid(&source));
    for (key, maximum) in [
        ("maximumOperations", 100_000),
        ("maximumOutputBytes", 2_097_152),
    ] {
        for value in [1, maximum] {
            source["functions"][0]["limits"] = json!({key:value});
            assert!(schema.is_valid(&source));
            read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
        }
        for value in [0, maximum + 1] {
            source["functions"][0]["limits"] = json!({key:value});
            assert!(!schema.is_valid(&source));
        }
    }
    source = facility();
    source["actions"][1]["execution"]["proposal"]["reviewContext"]["fields"]["extraPublicName"] =
        json!({"type":"input","input":"city"});
    assert!(schema.is_valid(&source));
    source["actions"][1]["execution"]["proposal"]["reviewContext"]["fields"]["bad-name"] =
        json!({"type":"input","input":"city"});
    assert!(!schema.is_valid(&source));
    source = facility();
    source["actions"][1]["commitGuards"]["targets"] = json!([
        {"input":"facility","field":"signed-value","atLeast":i64::MIN},
        {"input":"facility","field":"signed-value","atMost":i64::MAX}
    ]);
    assert!(schema.is_valid(&source));
}

#[cfg(feature = "schema")]
#[test]
fn named_types_keep_record_attributes_and_reject_them_on_action_inputs() {
    let documents = registry_breg::schema::documents().unwrap();
    let document: Value =
        serde_json::from_str(&documents[registry_breg::schema::REGISTRY_PROJECT_SCHEMA_FILE])
            .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&document)
        .unwrap();
    let mut source = facility();
    source["recordTypes"][0]["fields"][0] = json!({
        "id":"name","typeRef":"city","required":true,"classification":"restricted",
        "encrypted":true,"pattern":"[A-Z]"
    });
    assert!(schema.is_valid(&source));
    read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    source["actions"][1]["inputs"][2]["encrypted"] = json!(true);
    assert!(!schema.is_valid(&source));
    assert!(read_project_yaml("registry.yaml", &bytes(&source)).is_err());
}

#[cfg(feature = "schema")]
#[test]
fn module_schema_includes_the_readers_named_type_alternative() {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
        "id":"local-module","version":"0.1.0","valueTypes":{"short-label":{"type":"string","maximumLength":40}},
        "recordTypes":[{"id":"entry","route":"entries","primaryDataset":"directory","mutationMode":"mutable",
            "fields":[{"id":"label","typeRef":"short-label","classification":"internal"}]}]});
    read_module_yaml("module.yaml", &bytes(&source)).unwrap();
    let documents = registry_breg::schema::documents().unwrap();
    let document: Value =
        serde_json::from_str(&documents[registry_breg::schema::REGISTRY_MODULE_SCHEMA_FILE])
            .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&document)
        .unwrap();
    assert!(schema.is_valid(&source));
}
