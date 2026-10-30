// SPDX-License-Identifier: Apache-2.0
//! Owner-generated contracts constrain computed inputs and synthetic replies.
use registry_coordinator::{authoring, definition::Definition, scenarios};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn workflow(uses: &str) -> Value {
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "contract-imports", "version": "1"},
        "operations": {"request": {"uses": uses, "connection": "source"}},
        "workflow": {
            "input": {"type": "object"}, "deadlineSeconds": 300, "start": "call",
            "steps": {
                "call": {"type": "call", "operation": "request",
                    "input": {"type": "input"}, "next": "done"},
                "done": {"type": "finish", "outcome": "accepted"}
            },
            "outcomes": {"accepted": {"type": "null"}}
        }
    })
}

fn write_project(root: &Path, project: &Value, export: &Value, input: Value, reply: Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(root.join("contract.json"), export.to_string()).unwrap();
    let cases = json!({
        "apiVersion": scenarios::API_VERSION, "kind": scenarios::KIND,
        "cases": [{"id": "contracted", "admittedAt": "2026-10-09T09:00:00Z", "input": input,
            "replies": {"call": [{"type": "success", "value": reply}]},
            "expect": {"path": ["call", "done"], "state": "completed",
                "outcome": {"type": "named", "value": "accepted"}}}]
    });
    fs::write(root.join("scenarios.yaml"), cases.to_string()).unwrap();
}

fn cli(root: &Path, command: &str) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", command, "--project"])
        .arg(root)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

fn record_schema() -> Value {
    json!({"$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:breg:record-type:licence", "type": "object", "additionalProperties": false,
        "required": ["licenceNumber", "holder"],
        "properties": {"licenceNumber": {"type": "string"}, "holder": {"type": "string"}}})
}

fn record(domain_data: Value) -> Value {
    json!({"data": {"recordIdentifier": "r-1", "revisionIdentifier": "v-1", "domainData": domain_data},
        "meta": {"registryIdentifier": "registry", "datasetIdentifier": "licences", "recordTypeIdentifier": "licence"}})
}

#[test]
fn read_record_output_schema_accepts_the_registry_record_type_member() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/coordinator/generated/operations/breg.read-record.v1.output.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let mut response = record(json!({"licenceNumber": "LIC-1"}));
    assert!(validator.is_valid(&response));
    let meta = response["meta"].as_object_mut().unwrap();
    assert_eq!(meta.remove("recordTypeIdentifier"), Some(json!("licence")));
    assert!(!validator.is_valid(&response));
}

#[test]
fn read_record_import_checks_names_without_requiring_visible_fields_or_value_types() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("breg.read-record/v1");
    project["contracts"] = json!({"licence": {"type": "breg", "source": "contract.json"}});
    project["operations"]["request"]["record"] = json!({"contract": "licence"});
    let input = json!({"collection": "licences", "recordId": "r-1"});
    write_project(
        root.path(),
        &project,
        &record_schema(),
        input.clone(),
        record(json!({"licence-number": "LIC-1"})),
    );
    let definition = Definition::load(root.path()).unwrap();
    let cases = scenarios::load(&root.path().join("scenarios.yaml")).unwrap();
    let error = scenarios::check(&definition, &cases)
        .err()
        .expect("unknown record field must fail");
    assert_eq!(error.code, "scenario.reply-output");
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.scenario.reply-output"
    );
    for data in [
        json!({"licenceNumber": "LIC-1"}),
        json!({}),
        json!({"licenceNumber": 7}),
    ] {
        write_project(
            root.path(),
            &project,
            &record_schema(),
            input.clone(),
            record(data),
        );
        let (exit, report) = cli(root.path(), "test");
        assert_eq!(exit, 0, "{report}");
    }
    let snapshot = definition.snapshot().unwrap();
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.digest, definition.digest);
}

/// An operation id, its request, and a builder for a reply holding the given `domainData`.
type ProvenanceRead = (&'static str, Value, fn(Value) -> Value);

/// The operations that return a record's `domainData` besides
/// `breg.read-record/v1`.
fn provenance_reads() -> Vec<ProvenanceRead> {
    fn read_v2(domain_data: Value) -> Value {
        let mut reply = record(domain_data);
        reply["provenance"] = json!({"recordIdentifier": "r-1", "revisionIdentifier": "v-1",
            "observedAt": "2026-10-09T09:00:00Z"});
        reply
    }
    fn lookup(domain_data: Value) -> Value {
        json!({"recordIdentifier": "r-1", "revisionIdentifier": "v-1", "domainData": domain_data,
            "provenance": {"recordIdentifier": "r-1", "revisionIdentifier": "v-1",
                "observedAt": "2026-10-09T09:00:00Z"}})
    }
    vec![
        (
            "breg.read-record/v2",
            json!({"collection": "licences", "recordId": "r-1"}),
            read_v2,
        ),
        (
            "breg.lookup-record/v1",
            json!({"entity": "licences", "selector": "by-number",
                "values": {"licenceNumber": "LIC-1"}}),
            lookup,
        ),
    ]
}

#[test]
fn a_record_import_narrows_the_record_a_provenance_read_returns() {
    for (uses, input, reply) in provenance_reads() {
        let root = tempfile::tempdir().unwrap();
        let mut project = workflow(uses);
        project["contracts"] = json!({"licence": {"type": "breg", "source": "contract.json"}});
        project["operations"]["request"]["record"] = json!({"contract": "licence"});
        write_project(
            root.path(),
            &project,
            &record_schema(),
            input.clone(),
            reply(json!({"licence-number": "LIC-1"})),
        );
        let (exit, report) = cli(root.path(), "test");
        assert_eq!(exit, 1, "{uses}: {report}");
        assert_eq!(
            report["diagnostics"][0]["code"], "coordinator.scenario.reply-output",
            "{uses}: {report}"
        );
        for data in [
            json!({"licenceNumber": "LIC-1"}),
            json!({}),
            json!({"licenceNumber": 7}),
        ] {
            write_project(
                root.path(),
                &project,
                &record_schema(),
                input.clone(),
                reply(data),
            );
            let (exit, report) = cli(root.path(), "test");
            assert_eq!(exit, 0, "{uses}: {report}");
        }
        let definition = Definition::load(root.path()).unwrap();
        let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
        assert_eq!(restored.digest, definition.digest, "{uses}");
    }
}

#[test]
fn a_provenance_read_without_a_record_import_keeps_its_open_contract() {
    for (uses, input, reply) in provenance_reads() {
        let root = tempfile::tempdir().unwrap();
        write_project(
            root.path(),
            &workflow(uses),
            &json!({}),
            input,
            reply(json!({"licence-number": "LIC-1"})),
        );
        let (exit, report) = cli(root.path(), "test");
        assert_eq!(exit, 0, "{uses}: {report}");
    }
}

#[test]
fn a_record_import_is_refused_on_an_operation_that_returns_no_record() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("breg.submit-proposal/v1");
    project["contracts"] = json!({"licence": {"type": "breg", "source": "contract.json"}});
    project["operations"]["request"]["record"] = json!({"contract": "licence"});
    write_project(
        root.path(),
        &project,
        &record_schema(),
        json!({}),
        json!({}),
    );
    let (exit, report) = cli(root.path(), "check");
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/operations/request/record"
    );
    assert_eq!(
        report["diagnostics"][0]["message"],
        "only breg.read-record/v1, breg.read-record/v2, breg.lookup-record/v1 or breg.read-in-force/v1 accept a record contract selection"
    );
}

#[test]
fn read_record_selection_refuses_other_contracts_and_wrong_operations() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("breg.read-record/v1");
    project["contracts"] = json!({"licence": {"type": "breg", "source": "contract.json"}});
    project["operations"]["request"]["record"] = json!({"contract": "licence"});
    for export in [
        json!({"type": "object", "properties": {}}),
        json!({
        "apiVersion": "id.registrystack.org/formats/breg/action-contracts/v1",
        "kind": "BRegActionContracts", "actions": []}),
    ] {
        write_project(root.path(), &project, &export, json!({}), record(json!({})));
        let (exit, report) = cli(root.path(), "check");
        assert_eq!(exit, 1, "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "coordinator.operation.contract-invalid"
        );
    }
    project["operations"]["request"]["uses"] = json!("external.get/v1");
    write_project(
        root.path(),
        &project,
        &record_schema(),
        json!({}),
        json!({}),
    );
    let (exit, report) = cli(root.path(), "check");
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/operations/request/record"
    );
}

fn template_contract() -> Value {
    json!({"apiVersion": "id.registrystack.org/formats/messaging/template-contracts/v1",
        "kind": "MessagingTemplateContracts", "templates": [{"id": "licence-issued", "version": "1",
            "locales": ["en", "fr"], "dataSchema": {
                "type": "object", "additionalProperties": false, "required": ["name", "licenceNumber"],
                "properties": {"name": {"type": "string"}, "licenceNumber": {"$ref": "#/$defs/number"}},
                "$defs": {"number": {"type": "string"}}}}]})
}

fn message(data: Value) -> Value {
    json!({"senderProfile": "transactional", "to": {"email": "ada@example.invalid"},
        "template": {"id": "licence-issued", "version": "1"}, "locale": "en", "data": data})
}

fn receipt() -> Value {
    json!({"id": "00000000-0000-4000-8000-000000000001", "status": "queued",
        "links": {"self": "/v1/messages/00000000-0000-4000-8000-000000000001",
            "cancel": "/v1/messages/00000000-0000-4000-8000-000000000001/cancel"}})
}

#[test]
fn template_import_checks_computed_data_and_keeps_local_schema_references() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("messaging.submit-message/v1");
    project["contracts"] = json!({"notices": {"type": "messaging", "source": "contract.json"}});
    project["operations"]["request"]["template"] =
        json!({"contract": "notices", "id": "licence-issued", "version": "1"});
    project["functions"] = json!({"message": {"runtime": "rhai", "source": "functions.rhai", "entrypoint": "message",
        "inputs": {"input": {"type": "object"}}, "output": {"type": "object"}}});
    project["workflow"]["steps"]["call"]["input"] =
        json!({"type": "function", "function": "message", "inputs": {"input": {"type": "input"}}});
    fs::write(
        root.path().join("functions.rhai"),
        "fn message(args) { args.input }",
    )
    .unwrap();
    let reply = receipt();
    write_project(
        root.path(),
        &project,
        &template_contract(),
        message(json!({"name": "Ada", "licenceNo": "L1"})),
        reply.clone(),
    );
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.scenario.call-input"
    );
    let good = message(json!({"name": "Ada", "licenceNumber": "L1"}));
    write_project(
        root.path(),
        &project,
        &template_contract(),
        good.clone(),
        reply,
    );
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 0, "{report}");
    let definition = Definition::load(root.path()).unwrap();
    let input = &definition.workflow.operations["request"].input;
    let validator = registry_coordinator::contracts::OperationContract::new(
        input.clone(),
        json!({}),
        None,
        None,
    )
    .unwrap();
    for bad in [
        {
            let mut v = good.clone();
            v["locale"] = json!("de");
            v
        },
        {
            let mut v = good.clone();
            v["template"]["version"] = json!("2");
            v
        },
        {
            let mut v = good.clone();
            v["data"]["licenceNumber"] = json!(7);
            v
        },
        json!({"senderProfile": "transactional", "to": {"email": "ada@example.invalid"}, "content": {"text": "hello"}}),
    ] {
        assert!(validator.check_input(&bad).is_err(), "{bad}");
    }
    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
}

#[test]
fn template_selection_refuses_missing_versions_and_wrong_contract_products() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("messaging.submit-message/v1");
    project["contracts"] = json!({"notices": {"type": "messaging", "source": "contract.json"}});
    for (id, version) in [("missing", "1"), ("licence-issued", "2")] {
        project["operations"]["request"]["template"] =
            json!({"contract": "notices", "id": id, "version": version});
        write_project(
            root.path(),
            &project,
            &template_contract(),
            json!({}),
            json!({}),
        );
        let (exit, report) = cli(root.path(), "check");
        assert_eq!(exit, 1, "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "coordinator.operation.contract-invalid"
        );
        assert_eq!(
            report["diagnostics"][0]["path"],
            "/operations/request/template"
        );
    }
    project["operations"]["request"]["template"]["version"] = json!("1");
    write_project(
        root.path(),
        &project,
        &record_schema(),
        json!({}),
        json!({}),
    );
    let (exit, report) = cli(root.path(), "check");
    assert_eq!(exit, 1, "{report}");
}

#[test]
fn unbound_operations_retain_their_open_contracts() {
    for (uses, input, reply) in [
        (
            "breg.read-record/v1",
            json!({"collection": "licences", "recordId": "r-1"}),
            record(json!({"licence-number": "L1"})),
        ),
        (
            "messaging.submit-message/v1",
            json!({"senderProfile": "transactional", "to": {"email": "ada@example.invalid"}, "content": {"text": "hello"}}),
            receipt(),
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write_project(root.path(), &workflow(uses), &json!({}), input, reply);
        let (exit, report) = cli(root.path(), "test");
        assert_eq!(exit, 0, "{report}");
    }
}

#[test]
fn explain_includes_authored_event_triggers_in_json_and_human_output() {
    let root = tempfile::tempdir().unwrap();
    let mut project = workflow("breg.read-record/v1");
    let trigger = json!({"source": "licensing", "eventType": "licence-created-v1",
        "dataSchema": "urn:example:licence-created:v1", "event": {"type": "object"},
        "input": {"type": "input"}});
    project["workflow"]["eventTriggers"] = json!({"licence-created": trigger});
    write_project(
        root.path(),
        &project,
        &json!({}),
        json!({"collection": "licences", "recordId": "r-1"}),
        record(json!({})),
    );
    let (exit, report) = cli(root.path(), "explain");
    assert_eq!(exit, 0, "{report}");
    assert_eq!(
        report["eventTriggers"]["licence-created"],
        json!({
        "source": trigger["source"], "eventType": trigger["eventType"], "dataSchema": trigger["dataSchema"],
        "event": trigger["event"], "input": trigger["input"]})
    );
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["explain", "--project"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("licence-created: licensing licence-created-v1"),
        "{text}"
    );
    project["workflow"]
        .as_object_mut()
        .unwrap()
        .remove("eventTriggers");
    fs::write(root.path().join("workflow.yaml"), project.to_string()).unwrap();
    let (exit, report) = cli(root.path(), "explain");
    assert_eq!(exit, 0, "{report}");
    assert_eq!(report["eventTriggers"], json!({}));
}
