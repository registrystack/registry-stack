// SPDX-License-Identifier: Apache-2.0
use registry_breg::contract::{
    parse_project_json, read_module_yaml, read_project_yaml, ModuleAssetSource,
};
use registry_breg::{compile_project, compile_project_with_assets, CompileProfile};
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

fn authored_display() -> Value {
    registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../products/breg/fixtures/authoring-display/registry.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value()
}

#[test]
fn presentation_members_use_the_shared_display_text_reader() {
    for base in [
        "/accessProfiles/0/display",
        "/statisticalDatasets/0/display",
        "/recordTypes/0/hooks/0/display",
        "/actions/0/execution/proposal/hooks/0/display",
    ] {
        for member in ["label", "description"] {
            let mut source = authored_display();
            let pointer = format!("{base}/{member}");
            *source.pointer_mut(&pointer).unwrap() = json!("safe\u{202e}text");
            refusal(&source, &pointer, "config.invalid-value");
        }
    }
}

#[test]
fn presentation_duplicates_are_scoped_to_their_own_kind() {
    let cases = [
        ("/accessProfiles", "breg.access-profile.duplicate-label"),
        (
            "/statisticalDatasets",
            "breg.statistical-dataset.duplicate-label",
        ),
        ("/recordTypes/0/hooks", "breg.hook.duplicate-label"),
        (
            "/actions/0/execution/proposal/hooks",
            "breg.proposal-hook.duplicate-label",
        ),
    ];
    let mut source = authored_display();
    for (base, _) in cases {
        source.pointer_mut(base).unwrap()[0]["display"]["label"] = json!("Reviewed label");
    }
    let decoded = read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    assert_eq!(decoded.document.warnings().warning_count(), 0);

    for (base, code) in cases {
        let mut duplicate = source.clone();
        let entries = duplicate.pointer_mut(base).unwrap().as_array_mut().unwrap();
        let mut second = entries[0].clone();
        second["id"] = json!("second-definition");
        second["display"]["label"] = json!("REVIEWED\u{200b} LABEL");
        entries.push(second);
        let decoded = read_project_yaml("registry.yaml", &bytes(&duplicate)).unwrap();
        let report = decoded.document.warnings();
        let warnings = report.diagnostics();
        assert_eq!(warnings.len(), 1, "{}", report.render_human());
        assert_eq!(warnings[0].code, code);
        assert_eq!(warnings[0].path, format!("{base}/1/display/label"));
        assert_eq!(
            warnings[0].related[0].path,
            format!("{base}/0/display/label")
        );
        assert!(warnings[0].message.contains("second-definition"));
    }
}

#[test]
fn profile_and_hook_labels_follow_module_extension_namespaces() {
    let mut project = authored_display();
    project["modules"] = json!([{"id":"extension","version":"0.1.0"}]);
    project["accessProfiles"][0]["display"]["label"] = json!("Reader");
    project["recordTypes"][0]["hooks"][0]["display"]["label"] = json!("Notification");
    let profile = |id: &str| {
        json!({
            "id":id,"display":{"label":"RE\u{200b}ADER"},
            "principalClaim":"registry_principal","requiredScopes":["directory:read"],
            "operations":["get"],"readableFields":["code"],"rowBoundaries":"unrestricted"
        })
    };
    let hook = |id: &str| {
        json!({
            "id":id,"display":{"label":"NOTI\u{200b}FICATION"},
            "phase":"after","trigger":"created","projection":["code"],
            "handler":{"type":"url","destinationId":"entry-events"}
        })
    };
    let mut module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule","id":"extension","version":"0.1.0",
        "extendRecordTypes":[
            {"recordType":"entry","accessProfiles":[profile("module-reader")],"hooks":[hook("module-notice")]},
            {"recordType":"entry","accessProfiles":[profile("other-reader")],"hooks":[hook("other-notice")]}
        ]
    });
    let decoded = read_module_yaml("module.yaml", &bytes(&module)).unwrap();
    let report = decoded.document.warnings();
    for code in [
        "breg.access-profile.duplicate-label",
        "breg.hook.duplicate-label",
    ] {
        assert_eq!(
            report
                .diagnostics()
                .iter()
                .filter(|item| item.code == code)
                .count(),
            1
        );
    }
    let project = read_project_yaml("registry.yaml", &bytes(&project))
        .unwrap()
        .value;
    let compiled = compile_project(&project, &[decoded.value], CompileProfile::Authoring).unwrap();
    for code in [
        "breg.access-profile.duplicate-label",
        "breg.hook.duplicate-label",
    ] {
        let findings = compiled
            .findings()
            .iter()
            .filter(|item| item.code == code)
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 2, "cross-file pairs only: {findings:?}");
        assert!(findings.iter().all(|item| item
            .path
            .starts_with("modules[id=extension].extendRecordTypes[recordType=entry]")));
    }
    module["extendRecordTypes"][0]["accessProfiles"][0]["display"]["label"] =
        json!("unsafe\u{202e}");
    let report = read_module_yaml("module.yaml", &bytes(&module)).unwrap_err();
    assert!(report.diagnostics().iter().any(|item| {
        item.code == "config.invalid-value"
            && item.path == "/extendRecordTypes/0/accessProfiles/0/display/label"
    }));
}

fn implicit_unique_constraint_id() -> String {
    let project = parse_project_json(
        serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
            "kind":"BRegProject",
            "project":{
                "id":"constraint-collisions",
                "version":"1",
                "defaultLanguage":"en",
                "canonicalBaseIri":"https://example.test"
            },
            "datasets":[{"id":"records"}],
            "recordTypes":[{
                "id":"item",
                "primaryDataset":"records",
                "route":"items",
                "mutationMode":"mutable",
                "fields":[{
                    "id":"code",
                    "type":"string",
                    "maximumLength":16,
                    "classification":"internal"
                }],
                "constraints":[{"type":"unique","fields":["code"]}]
            }]
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let compiled = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    compiled.entities()["item"]
        .constraints
        .keys()
        .next()
        .expect("the implicit constraint has an effective identifier")
        .clone()
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
fn display_text_is_refused_at_each_breg_authoring_boundary() {
    for path in [
        "/recordTypes/0/display/label",
        "/actions/1/plan/refusals/0/label",
    ] {
        let mut source = facility();
        *source.pointer_mut(path).unwrap() = json!("safe\u{202e}text");
        refusal(&source, path, "config.invalid-value");
    }

    let mut source = facility();
    source["manifestProjection"] = json!({
        "accessProfile":"facility-reader",
        "classificationCeiling":"internal",
        "catalog":{
            "baseUrl":"https://facility-registry.example.gov",
            "title":"safe\u{202e}text",
            "publisher":{"id":"facility-authority","name":"Facility authority"}
        },
        "publicService":{"id":"facility-service","title":"Facility registry"},
        "datasets":[{"id":"facility-registry","title":"Facility registry"}],
        "dataServices":[{
            "id":"facility-api",
            "title":"Facility API",
            "endpointUrl":"https://facility-registry.example.gov",
            "servesDatasets":["facility-registry"]
        }]
    });
    refusal(
        &source,
        "/manifestProjection/catalog/title",
        "config.invalid-value",
    );

    let mut source = facility();
    source["recipients"] = json!({
        "organizations":[{
            "id":"privacy-office",
            "name":"Privacy office",
            "contact":"safe\u{202e}text",
            "clients":[]
        }]
    });
    refusal(
        &source,
        "/recipients/organizations/0/contact",
        "config.invalid-value",
    );

    source["recipients"]["organizations"][0]["contact"] = json!("مكتب الخصوصية");
    read_project_yaml("registry.yaml", &bytes(&source))
        .expect("multilingual recipient contact remains accepted");
}

#[test]
fn lookalike_local_ids_name_and_locate_both_definitions() {
    let mut source = facility();
    let mut lookalike = source["accessProfiles"][1].clone();
    lookalike["id"] = json!("facility_reader");
    let second_index = source["accessProfiles"].as_array().unwrap().len();
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(lookalike);

    let report = read_project_yaml("registry.yaml", &bytes(&source)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.access-profile.id-collision")
        .expect("lookalike access profiles are refused");
    assert_eq!(
        diagnostic.path,
        format!("/accessProfiles/{second_index}/id")
    );
    assert!(diagnostic.message.contains("facility-reader"));
    assert!(diagnostic.message.contains("facility_reader"));
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(diagnostic.related[0].path, "/accessProfiles/1/id");
    assert!(diagnostic.related[0].line.is_some());
}

#[test]
fn implicit_constraint_ids_collide_at_the_constraint_list_item() {
    let explicit = implicit_unique_constraint_id().replace('-', "_");
    let source = format!(
        r#"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: constraint-collisions
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://example.test
datasets:
  - id: records
recordTypes:
  - id: item
    primaryDataset: records
    route: items
    mutationMode: mutable
    fields:
      - id: code
        type: string
        maximumLength: 16
        classification: internal
    constraints:
      - type: unique
        fields: [code]
      - id: {explicit}
        type: unique
        fields: [code]
"#
    );

    let report = read_project_yaml("registry.yaml", source.as_bytes()).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.constraint.id-collision")
        .unwrap_or_else(|| {
            panic!(
                "missing effective constraint collision: {}",
                report.render_human()
            )
        });
    assert_eq!(diagnostic.path, "/recordTypes/0/constraints/1/id");
    let site = diagnostic
        .source
        .as_ref()
        .expect("located explicit constraint id");
    assert_eq!((site.line, site.column), (Some(23), Some(13)));
    assert_eq!(diagnostic.related.len(), 1);
    let related = &diagnostic.related[0];
    assert_eq!(related.path, "/recordTypes/0/constraints/0");
    assert_eq!((related.line, related.column), (Some(21), Some(9)));
}

#[test]
fn fixed_action_effect_collisions_include_implicit_ids_at_the_list_item() {
    const HEAD: &str = r#"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: effect-collisions
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://example.test
"#;
    let cases = [
        (
            format!(
                "{HEAD}actions:\n  - id: update-item\n    execution: {{mode: immediate}}\n    plan:\n      type: fixed\n      effects:\n        - target: {{fromInput: item}}\n          operation: patch\n          set: {{name: {{value: first}}}}\n        - id: effect_1\n          target: {{fromInput: item}}\n          operation: patch\n          set: {{name: {{value: second}}}}\n"
            ),
            ("/actions/0/plan/effects/1/id", 17, 15),
            ("/actions/0/plan/effects/0", 14, 11),
        ),
        (
            format!(
                "{HEAD}actions:\n  - id: create-and-update\n    execution: {{mode: immediate}}\n    plan:\n      type: fixed\n      effects:\n        - id: effect_2\n          target: {{recordType: item}}\n          operation: create\n          set: {{name: {{value: created}}}}\n        - target: {{fromInput: item}}\n          operation: patch\n          set: {{name: {{value: updated}}}}\n"
            ),
            ("/actions/0/plan/effects/1", 18, 11),
            ("/actions/0/plan/effects/0/id", 14, 15),
        ),
    ];

    for (source, primary, related) in cases {
        let report = read_project_yaml("registry.yaml", source.as_bytes()).unwrap_err();
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.action-effect.id-collision")
            .unwrap_or_else(|| {
                panic!(
                    "effective Action effect identifiers are one namespace: {}",
                    report.render_human()
                )
            });
        let site = diagnostic.source.as_ref().expect("located primary effect");
        assert_eq!(diagnostic.path, primary.0);
        assert_eq!(site.file, "registry.yaml");
        assert_eq!((site.line, site.column), (Some(primary.1), Some(primary.2)));
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.related[0].path, related.0);
        assert_eq!(diagnostic.related[0].file, "registry.yaml");
        assert_eq!(
            (diagnostic.related[0].line, diagnostic.related[0].column),
            (Some(related.1), Some(related.2))
        );
    }
}

#[test]
fn hook_ids_share_one_namespace_within_each_authored_file() {
    let hook = |id: &str| {
        json!({
            "id":id,
            "phase":"after",
            "trigger":"created",
            "projection":[]
        })
    };
    let mut project = facility();
    project["recordTypes"][0]["hooks"] = json!([hook("notify-user")]);
    project["recordTypes"][1]["hooks"] = json!([hook("notify_user")]);
    let report = read_project_yaml("registry.yaml", &bytes(&project)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.hook.id-collision")
        .expect("project hooks share one identifier namespace");
    assert_eq!(diagnostic.path, "/recordTypes/1/hooks/0/id");
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/hooks/0/id");
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert!(diagnostic.related[0].line.is_some());

    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[{
            "id":"entry",
            "route":"entries",
            "primaryDataset":"directory",
            "mutationMode":"mutable",
            "fields":[],
            "hooks":[hook("notify-user")]
        }],
        "extendRecordTypes":[{
            "recordType":"entry",
            "hooks":[hook("notify_user")]
        }]
    });
    let report = read_module_yaml("module.yaml", &bytes(&module)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.hook.id-collision")
        .expect("module record and extension hooks share one identifier namespace");
    assert_eq!(diagnostic.path, "/extendRecordTypes/0/hooks/0/id");
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/hooks/0/id");
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert!(diagnostic.related[0].line.is_some());
}

#[test]
fn timer_ids_share_positioned_record_type_namespaces_within_each_authored_file() {
    let timer = |id: &str| {
        json!({
            "id":id,
            "at":"created-at",
            "invoke":"activate-entry",
            "input":{}
        })
    };

    let mut project = facility();
    project["recordTypes"][0]["timers"] = json!([timer("activate-entry"), timer("activate_entry")]);
    let report = read_project_yaml("registry.yaml", &bytes(&project)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.timer.id-collision")
        .expect("project timers share one positioned Record type namespace");
    assert_eq!(diagnostic.path, "/recordTypes/0/timers/1/id");
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/timers/0/id");
    assert_eq!(diagnostic.source.as_ref().unwrap().file, "registry.yaml");
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert_eq!(diagnostic.related[0].file, "registry.yaml");
    assert!(diagnostic.related[0].line.is_some());

    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[{
            "id":"entry",
            "route":"entries",
            "primaryDataset":"directory",
            "mutationMode":"mutable",
            "fields":[],
            "timers":[timer("activate-entry")]
        }],
        "extendRecordTypes":[{
            "recordType":"entry",
            "timers":[timer("activate_entry")]
        }]
    });
    let report = read_module_yaml("module.yaml", &bytes(&module)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.timer.id-collision")
        .expect("module Record and extension timers share one positioned namespace");
    assert_eq!(diagnostic.path, "/extendRecordTypes/0/timers/0/id");
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/timers/0/id");
    assert_eq!(diagnostic.source.as_ref().unwrap().file, "module.yaml");
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert_eq!(diagnostic.related[0].file, "module.yaml");
    assert!(diagnostic.related[0].line.is_some());
}

#[test]
fn duplicate_authored_labels_warn_with_normalized_comparison_and_locations() {
    let mut source = facility();
    source["recordTypes"][0]["display"]["label"] = json!("Café");
    source["recordTypes"][1]["display"]["label"] = json!("CA\u{200b}FÉ");

    let decoded = read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    let report = decoded.document.warnings();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.record-type.duplicate-label")
        .expect("equivalent record type labels produce a warning");
    assert_eq!(diagnostic.path, "/recordTypes/1/display/label");
    assert!(diagnostic.message.contains("directory-entry"));
    assert!(diagnostic.message.contains("operator"));
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/display/label");
    assert!(diagnostic.related[0].line.is_some());
}

#[test]
fn action_refusal_labels_are_scoped_to_their_action() {
    let mut source = facility();
    let mut independent = source["actions"][1].clone();
    independent["id"] = json!("independent-correction");
    independent["display"]["label"] = json!("Independent correction");
    source["actions"].as_array_mut().unwrap().push(independent);

    let decoded = read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    assert!(decoded
        .document
        .warnings()
        .diagnostics()
        .iter()
        .all(|warning| warning.code != "breg.action-refusal.duplicate-label"));

    let refusal = source["actions"][1]["plan"]["refusals"][0].clone();
    source["actions"][1]["plan"]["refusals"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code":"same-action-peer","label":refusal["label"]}));
    let decoded = read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    let report = decoded.document.warnings();
    let warnings = report
        .diagnostics()
        .iter()
        .filter(|warning| warning.code == "breg.action-refusal.duplicate-label")
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].path, "/actions/1/plan/refusals/1/label");
    assert_eq!(
        warnings[0].related[0].path,
        "/actions/1/plan/refusals/0/label"
    );
}

#[test]
fn reader_refusals_keep_duplicate_label_warnings_for_projects_and_modules() {
    let mut project = facility();
    project["recordTypes"][0]["display"]["label"] = json!("Café");
    project["recordTypes"][1]["display"]["label"] = json!("CAFE\u{301}");
    let mut profile = project["accessProfiles"][1].clone();
    profile["id"] = json!("facility_reader");
    project["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(profile);
    let report = read_project_yaml("registry.yaml", &bytes(&project)).unwrap_err();
    for code in [
        "breg.record-type.duplicate-label",
        "breg.access-profile.id-collision",
    ] {
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code}: {report:#?}"
        );
    }

    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[
            {
                "id":"entry-one",
                "route":"entries",
                "primaryDataset":"directory",
                "mutationMode":"mutable",
                "display":{"label":"Directory entry"},
                "fields":[]
            },
            {
                "id":"entry_one",
                "route":"entry-copies",
                "primaryDataset":"directory",
                "mutationMode":"mutable",
                "display":{"label":"directory entry"},
                "fields":[]
            }
        ]
    });
    let report = read_module_yaml("module.yaml", &bytes(&module)).unwrap_err();
    for code in [
        "breg.record-type.duplicate-label",
        "breg.record-type.id-collision",
    ] {
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code}: {report:#?}"
        );
    }
}

#[test]
fn reader_refusals_sort_and_bound_warnings_with_integrity_errors_once() {
    let repeated_records = |last_id: &str| {
        (0..102)
            .map(|index| {
                let id = if index == 101 {
                    last_id.to_owned()
                } else {
                    format!("entry-{index}")
                };
                json!({
                    "id":id,
                    "route":format!("entries-{index}"),
                    "primaryDataset":"directory",
                    "mutationMode":"mutable",
                    "display":{"label":"Repeated entry"},
                    "fields":[]
                })
            })
            .collect::<Vec<_>>()
    };
    let mut project = facility();
    project["recordTypes"] = Value::from(repeated_records("entry_100"));
    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":repeated_records("entry_100")
    });

    for report in [
        read_project_yaml("registry.yaml", &bytes(&project)).unwrap_err(),
        read_module_yaml("module.yaml", &bytes(&module)).unwrap_err(),
    ] {
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(report.diagnostics().len(), 101);
        let overflow = report.diagnostics().last().unwrap();
        assert_eq!(overflow.code, "config.too-many-problems");
        assert_eq!(
            overflow.message,
            "2 more problems in this file are not shown"
        );
        assert_eq!(overflow.severity, registry_platform_yaml::Severity::Error);
        assert!(report.diagnostics()[..100].windows(2).all(|pair| {
            let site = |diagnostic: &registry_platform_yaml::Diagnostic| {
                diagnostic
                    .source
                    .as_ref()
                    .map(|source| (source.line, source.column))
            };
            site(&pair[0]) <= site(&pair[1])
        }));
    }
}

#[test]
fn duplicate_presentation_text_warns_in_each_breg_namespace() {
    let mut source = facility();
    source["project"]["defaultLanguage"] = json!("EN");
    let refusal = source["actions"][1]["plan"]["refusals"][0].clone();
    source["actions"][1]["plan"]["refusals"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code":"another-refusal","label":refusal["label"]}));
    source["recipients"] = json!({
        "organizations":[
            {"id":"alpha","name":"Café","contact":"a@example.test","clients":["alpha-client"]},
            {"id":"beta","name":"CAFE\u{301}","contact":"b@example.test","clients":["beta-client"]}
        ],
        "groups":[
            {"id":"north","name":"Reviewers","members":["alpha"]},
            {"id":"south","name":"reviewers","members":["beta"]},
            {"id":"shared","name":"CA\u{200b}FÉ","members":["alpha"]}
        ]
    });
    source["manifestProjection"] = json!({
        "accessProfile":"facility-reader",
        "classificationCeiling":"internal",
        "catalog":{
            "baseUrl":"https://facility-registry.example.gov",
            "title":"Facility catalog",
            "publisher":{"id":"facility-authority","name":"Facility authority"}
        },
        "publicService":{"id":"facility-service","title":"Facility registry"},
        "datasets":[
            {"id":"first","title":"Café"},
            {"id":"second","title":{"en":"CAFE\u{301}","fr":"Deuxième"}},
            {"id":"third","title":{"fr":"Café"}}
        ],
        "dataServices":[
            {"id":"first-api","title":"Registry API","endpointUrl":"https://example.test/first","servesDatasets":["first"]},
            {"id":"second-api","title":"registry api","endpointUrl":"https://example.test/second","servesDatasets":["second"]}
        ],
        "distributions":[
            {"id":"first-export","dataset":"first","title":"CSV export"},
            {"id":"second-export","dataset":"second","title":"csv export"}
        ],
        "entities":[
            {"id":"first-record","title":"Facility record"},
            {"id":"second-record","title":"facility record"}
        ],
        "vocabularies":[{
            "id":"status",
            "schemeIri":"https://example.test/status",
            "concepts":[
                {"code":"arbitrary code one","label":"Active"},
                {"code":"arbitrary code two","label":"active"}
            ]
        }]
    });

    let decoded = read_project_yaml("registry.yaml", &bytes(&source)).unwrap();
    let diagnostics = decoded.document.warnings();
    for (code, path) in [
        (
            "breg.action-refusal.duplicate-label",
            "/actions/1/plan/refusals/1/label",
        ),
        (
            "breg.recipient.duplicate-name",
            "/recipients/organizations/1/name",
        ),
        ("breg.recipient.duplicate-name", "/recipients/groups/1/name"),
        ("breg.recipient.duplicate-name", "/recipients/groups/2/name"),
        (
            "breg.manifest-dataset.duplicate-title",
            "/manifestProjection/datasets/1/title/en",
        ),
        (
            "breg.manifest-data-service.duplicate-title",
            "/manifestProjection/dataServices/1/title",
        ),
        (
            "breg.manifest-distribution.duplicate-title",
            "/manifestProjection/distributions/1/title",
        ),
        (
            "breg.manifest-entity.duplicate-title",
            "/manifestProjection/entities/1/title",
        ),
        (
            "breg.manifest-vocabulary-concept.duplicate-label",
            "/manifestProjection/vocabularies/0/concepts/1/label",
        ),
    ] {
        let diagnostic = diagnostics
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code && diagnostic.path == path)
            .unwrap_or_else(|| panic!("expected {code} at {path}"));
        assert_eq!(diagnostic.related.len(), 1);
    }

    let cross_kind = diagnostics
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.code == "breg.recipient.duplicate-name"
                && diagnostic.path == "/recipients/groups/2/name"
        })
        .expect("organization and group names share one warning namespace");
    assert_eq!(
        cross_kind.related[0].path,
        "/recipients/organizations/0/name"
    );
    assert_eq!(
        diagnostics
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "breg.manifest-dataset.duplicate-title")
            .count(),
        1,
        "the same text in another language is not a duplicate"
    );
    let concept = diagnostics
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.manifest-vocabulary-concept.duplicate-label")
        .unwrap();
    assert!(!concept.message.contains("arbitrary code"));
}

#[test]
fn module_extensions_share_their_target_record_type_namespaces() {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[{
            "id":"entry",
            "route":"entries",
            "primaryDataset":"directory",
            "mutationMode":"mutable",
            "fields":[{
                "id":"case-number",
                "type":"string",
                "maximumLength":40,
                "classification":"internal"
            }]
        }],
        "extendRecordTypes":[{
            "recordType":"entry",
            "fields":[{
                "id":"case_number",
                "type":"string",
                "maximumLength":40,
                "classification":"internal"
            }]
        }]
    });
    let report = read_module_yaml("module.yaml", &bytes(&source)).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.id-collision")
        .expect("a module extension shares the target record type's field namespace");
    assert_eq!(diagnostic.path, "/extendRecordTypes/0/fields/0/id");
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(diagnostic.related[0].path, "/recordTypes/0/fields/0/id");
}

#[test]
fn compiler_refuses_lookalike_ids_across_project_and_module_files() {
    let project = read_project_yaml("registry.yaml", &bytes(&facility()))
        .unwrap()
        .value;
    let module_source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[{
            "id":"directory_entry",
            "route":"module-directory-entries",
            "primaryDataset":"facility-registry",
            "mutationMode":"mutable",
            "fields":[{
                "id":"module-code",
                "type":"string",
                "maximumLength":40,
                "classification":"internal"
            }]
        }]
    });
    let module = read_module_yaml("module.yaml", &bytes(&module_source))
        .unwrap()
        .value;
    let failure = compile_project(&project, &[module], CompileProfile::Authoring).unwrap_err();
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.record-type.id-collision")
        .expect("the project and module share the record type namespace");
    assert_eq!(
        diagnostic.path,
        "modules[id=local-module].recordTypes[id=directory_entry].id"
    );
    assert!(diagnostic.message.contains("directory-entry"));
    assert!(diagnostic.message.contains("directory_entry"));
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(
        diagnostic.related[0].path,
        "recordTypes[id=directory-entry].id"
    );
    assert_eq!(
        diagnostic.related[0].message,
        "the first identifier is defined here"
    );
}

#[test]
fn compiler_warns_for_duplicate_labels_across_modules_and_extensions() {
    let mut project_source = facility();
    project_source["modules"] = json!([{"id":"local-module","version":"0.1.0"}]);
    project_source["functions"] = json!([]);
    project_source["actions"] = json!([]);
    project_source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .truncate(3);
    project_source["recordTypes"][0]["fields"][0]["display"] = json!({"label":"Café"});
    let project = read_project_yaml("registry.yaml", &bytes(&project_source))
        .unwrap()
        .value;
    let module_source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "recordTypes":[{
            "id":"module-entry",
            "route":"module-entries",
            "primaryDataset":"facility-registry",
            "mutationMode":"mutable",
            "display":{"label":"directory\u{200b} entry"},
            "fields":[{
                "id":"module-code",
                "type":"string",
                "maximumLength":40,
                "classification":"internal"
            }]
        }],
        "extendRecordTypes":[{
            "recordType":"directory-entry",
            "fields":[{
                "id":"alternate-name",
                "type":"string",
                "maximumLength":160,
                "classification":"public",
                "display":{"label":"CAFE\u{301}"}
            }]
        }]
    });
    let module = read_module_yaml("module.yaml", &bytes(&module_source))
        .unwrap()
        .value;
    let compiled = compile_project(&project, &[module], CompileProfile::Authoring).unwrap();

    let record = compiled
        .findings()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.record-type.duplicate-label")
        .expect("record labels are compared across project and module files");
    assert_eq!(
        record.path,
        "modules[id=local-module].recordTypes[id=module-entry].display.label"
    );
    assert!(record.message.contains("directory-entry"));
    assert!(record.message.contains("module-entry"));
    assert!(!record.message.contains("Directory entry"));
    assert_eq!(record.related.len(), 1);
    assert_eq!(
        record.related[0].path,
        "recordTypes[id=directory-entry].display.label"
    );
    assert_eq!(
        record.related[0].message,
        "the first display text is defined here"
    );

    let field = compiled
        .findings()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.duplicate-label")
        .expect("field labels are compared across extensions in another module");
    assert_eq!(
        field.path,
        "modules[id=local-module].extendRecordTypes[recordType=directory-entry].fields[id=alternate-name].display.label"
    );
    assert!(field.message.contains("name"));
    assert!(field.message.contains("alternate-name"));
    assert!(!field.message.contains("Café"));
    assert_eq!(field.related.len(), 1);
    assert_eq!(
        field.related[0].path,
        "recordTypes[id=directory-entry].fields[id=name].display.label"
    );
}

#[test]
fn compiler_scopes_refusal_labels_by_action_across_project_and_module() {
    let mut project_source = facility();
    project_source["modules"] = json!([{"id":"local-module","version":"0.1.0"}]);
    let mut permission = project_source["accessProfiles"][4]["permissions"]["actions"][0].clone();
    permission["action"] = json!("module-correct-address");
    project_source["accessProfiles"][4]["permissions"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(permission);
    let project = read_project_yaml("registry.yaml", &bytes(&project_source))
        .unwrap()
        .value;

    let mut function = project_source["functions"][0].clone();
    function["id"] = json!("module-address-plan");
    let mut action = project_source["actions"][1].clone();
    action["id"] = json!("module-correct-address");
    action["plan"]["function"] = json!("module-address-plan");
    action["display"]["label"] = json!("Module address correction");
    let module_source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"local-module",
        "version":"0.1.0",
        "valueTypes":project_source["valueTypes"].clone(),
        "functions":[function],
        "actions":[action]
    });
    let module = read_module_yaml("module.yaml", &bytes(&module_source))
        .unwrap()
        .value;
    let source =
        include_bytes!("../../../products/breg/examples/facility/plans/correct-address.rhai");
    let compiled = compile_project_with_assets(
        &project,
        &[module],
        &[
            ModuleAssetSource {
                module: None,
                path: "plans/correct-address.rhai".to_owned(),
                bytes: source.to_vec(),
            },
            ModuleAssetSource {
                module: Some("local-module".to_owned()),
                path: "plans/correct-address.rhai".to_owned(),
                bytes: source.to_vec(),
            },
        ],
        CompileProfile::Authoring,
    )
    .unwrap();
    assert!(compiled
        .findings()
        .iter()
        .all(|diagnostic| diagnostic.code != "breg.action-refusal.duplicate-label"));
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
