// SPDX-License-Identifier: Apache-2.0
//! Deployment and authoring boundaries for typed decision evaluations.
use registry_coordinator::{
    adapters::HttpAdapters,
    definition::Definition,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    runtime::{RuntimeConfig, API_VERSION, KIND},
    scenarios,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use wiremock::{
    matchers::{body_json, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn document() -> Value {
    json!({
        "apiVersion":API_VERSION,"kind":KIND,
        "secretProviders":{"environment":{}},
        "database":{"runtimeUrlRef":"secret:env/UNRESOLVED_DECISION_TEST_DATABASE",
            "migrationUrlRef":"secret:env/UNRESOLVED_DECISION_TEST_DATABASE"},
        "namespace":"coordinator_decision_test",
        "decisionConnections":{"assessor":{
            "protocol":"system-one","baseUrl":"https://decision.example.test/tenant",
            "model":"fixture-model","authorization":{"bearer":{
                "tokenRef":"secret:env/UNRESOLVED_DECISION_TEST_TOKEN","principal":"fixture-account"
            }}
        }}
    })
}

fn load(document: &Value) -> registry_coordinator::Result<RuntimeConfig> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    RuntimeConfig::load(&path)
}

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/decision-follow-up")
        .canonicalize()
        .unwrap()
}

#[test]
fn offline_decision_binding_checks_do_not_resolve_credentials() {
    let config = load(&document()).unwrap();
    assert!(config.connections.is_empty());
    assert!(config.external_http_connections.is_empty());
    let effective = config.document().unwrap();
    assert_eq!(
        effective["decisionConnections"]["assessor"]["attemptTimeoutMilliseconds"],
        8000
    );
    assert_eq!(
        effective["decisionConnections"]["assessor"]["maximumRequestBytes"],
        65536
    );
    assert_eq!(
        effective["decisionConnections"]["assessor"]["maximumResponseBytes"],
        65536
    );
    config.binding_digest().unwrap();

    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(&document()).unwrap()).unwrap();
    let check = RuntimeConfig::check_file(&path, false);
    assert!(!check.unavailable);
    assert!(check.diagnostics.is_empty());
}

#[test]
fn decision_binding_is_pinned_but_credential_rotation_is_not_a_new_command() {
    let original = document();
    let digest = load(&original).unwrap().binding_digest().unwrap();
    let mut rotated = original.clone();
    rotated["decisionConnections"]["assessor"]["authorization"]["bearer"]["tokenRef"] =
        json!("secret:env/ROTATED_DECISION_TEST_TOKEN");
    assert_eq!(load(&rotated).unwrap().binding_digest().unwrap(), digest);
    for (member, value) in [
        ("protocol", json!("openai-decisions")),
        ("baseUrl", json!("https://other.example.test/tenant")),
        ("model", json!("different-model")),
        ("attemptTimeoutMilliseconds", json!(7000)),
        ("maximumRequestBytes", json!(32768)),
        ("maximumResponseBytes", json!(32768)),
    ] {
        let mut changed = original.clone();
        changed["decisionConnections"]["assessor"][member] = value;
        assert_ne!(
            load(&changed).unwrap().binding_digest().unwrap(),
            digest,
            "{member}"
        );
    }
    let mut changed = original.clone();
    changed["decisionConnections"]["assessor"]["authorization"]["bearer"]["principal"] =
        json!("other-account");
    assert_ne!(load(&changed).unwrap().binding_digest().unwrap(), digest);
}

#[test]
fn decision_credentials_and_connection_names_fail_closed() {
    let mut missing_provider = document();
    missing_provider["decisionConnections"]["assessor"]["authorization"]["bearer"]["tokenRef"] =
        json!("secret:file/private-canary");
    let error = load(&missing_provider).err().unwrap();
    assert_eq!(
        error.field.as_deref(),
        Some("/decisionConnections/assessor/authorization/bearer/tokenRef")
    );
    assert!(!error.to_string().contains("private-canary"));
    let mut collision = document();
    collision["externalHttpConnections"] = json!({"assessor":{
        "baseUrl":"https://directory.example.test", "paths":["records"],"responseSchema":{"type":"object"}
    }});
    let error = load(&collision).err().unwrap();
    assert_eq!(
        error.field.as_deref(),
        Some("/decisionConnections/assessor")
    );
    let mut remote_public = document();
    remote_public["decisionConnections"]["assessor"]["authorization"] = json!({"local":{}});
    assert!(load(&remote_public).is_err());
    let mut absent = document();
    absent["decisionConnections"]["assessor"]
        .as_object_mut()
        .unwrap()
        .remove("authorization");
    assert!(load(&absent).is_err());
}

#[test]
fn named_decision_binding_is_required_and_other_connections_do_not_change_identity() {
    let root = example();
    let definition = Definition::load(&root).unwrap();
    let config = RuntimeConfig::load(&root.join("runtime.yaml")).unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    let digest = config.binding_digest_for(&definition.workflow).unwrap();
    let mut extra = config.clone();
    let binding = extra.decision_connections["assessor"].clone();
    extra
        .decision_connections
        .insert("unrelated".into(), binding);
    assert_eq!(
        extra.binding_digest_for(&definition.workflow).unwrap(),
        digest
    );
    extra.decision_connections.remove("assessor");
    let error = extra.validate_workflow(&definition.workflow).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("decisionConnections.assessor"));
}

#[cfg(feature = "schema")]
#[test]
fn decision_config_schema_matches_reader_for_authorization_and_bounds() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(validator.is_valid(&document()));
    for (member, value) in [
        ("attemptTimeoutMilliseconds", json!(8001)),
        ("maximumRequestBytes", json!(0)),
        ("maximumResponseBytes", json!(65537)),
        ("protocol", json!("unregistered-provider")),
        (
            "authorization",
            json!({"bearer":{"tokenRef":"inline-secret-canary","principal":"test"}}),
        ),
        (
            "authorization",
            json!({"local":{},"bearer":{"tokenRef":"secret:env/TOKEN","principal":"test"}}),
        ),
    ] {
        let mut d = document();
        d["decisionConnections"]["assessor"][member] = value;
        assert!(!validator.is_valid(&d), "schema accepted {member}");
        assert!(load(&d).is_err(), "reader accepted {member}");
    }
}

#[tokio::test]
async fn deployed_decision_adapter_requires_frozen_preparation_and_preserves_prefix() {
    let server = MockServer::start().await;
    let mut d = document();
    d["decisionConnections"]["assessor"]["baseUrl"] = json!(format!("{}/tenant", server.uri()));
    d["decisionConnections"]["assessor"]["authorization"] = json!({"local":{}});
    let adapters = HttpAdapters::new(&load(&d).unwrap()).unwrap();
    let input = json!({"state":{"summary":"synthetic"},"questions":{"ready":{"type":"predicate","instructions":"Ready?"}}});
    let request = CallRequest {
        connection: "assessor".into(),
        operation: Operation::EvaluateDecision,
        input: input.clone(),
        idempotency_key: None,
    };
    assert!(matches!(
        adapters.call(&request).await,
        CallOutcome::Refused { .. }
    ));
    assert!(matches!(
        adapters.call_prepared(&request, None).await,
        CallOutcome::Refused { .. }
    ));
    let Ok(Some(prepared)) = adapters.prepare(&request).await else {
        panic!("inert preparation must succeed")
    };
    assert!(server.received_requests().await.unwrap().is_empty());
    Mock::given(method("POST")).and(path("/tenant/v1/systemone"))
        .and(body_json(json!({"model":"fixture-model","state":{"summary":"synthetic"},"questions":{"ready":{"type":"noul","instructions":"Ready?"}}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model-1","answers":{"ready":{"type":"noul","noul":0.8}},"usage":{"input_tokens":2,"output_tokens":0}})))
        .expect(1).mount(&server).await;
    let CallOutcome::Success(result) = adapters.call_prepared(&request, Some(&prepared)).await
    else {
        panic!("fixture evaluation must succeed")
    };
    assert_eq!(result["answers"]["ready"]["probability"], 0.8);
    assert_eq!(result["returnedModel"], "fixture-model-1");
    let mut substituted = request;
    substituted.input["state"]["summary"] = json!("different");
    assert!(matches!(
        adapters.call_prepared(&substituted, Some(&prepared)).await,
        CallOutcome::Refused { .. }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn decision_example_exercises_policy_without_network_and_preserves_data_minimization() {
    let root = example();
    let definition = Definition::load(&root).unwrap();
    let scenarios = scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let reports = registry_coordinator::scenarios::check(&definition, &scenarios).unwrap();
    assert_eq!(reports.len(), 8);
    for report in &reports {
        assert!(report.call_attempts["assess"] <= 3);
    }
    let request = definition
        .evaluate("assess", &scenarios.cases[0].input, &Default::default())
        .unwrap();
    assert!(request["state"].get("applicationId").is_none());
    assert_eq!(
        request["state"]["summary"],
        scenarios.cases[0].input["summary"]
    );
    for name in [
        "lost-decision-reply-stops-before-action",
        "malformed-decision-reply-stops-before-action",
    ] {
        let report = reports.iter().find(|report| report.name == name).unwrap();
        assert_eq!(report.state, "uncertain");
        assert_eq!(report.call_attempts["assess"], 1);
        assert!(!report.call_attempts.contains_key("request-information"));
    }
}

#[test]
fn decision_runtime_preserves_unknown_key_positions_and_defers_environment_values() {
    for branch in ["bearer", "local"] {
        let mut d = document();
        if branch == "local" {
            d["decisionConnections"]["assessor"]["baseUrl"] = json!("http://127.0.0.1:11434");
            d["decisionConnections"]["assessor"]["authorization"] = json!({"local":{}});
        }
        d["decisionConnections"]["assessor"]["authorization"][branch]["unexpected"] =
            json!("private-canary");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap().join("runtime.yaml");
        std::fs::write(&path, serde_json::to_string_pretty(&d).unwrap()).unwrap();
        let checked = RuntimeConfig::check_file(&path, false);
        let finding = checked
            .diagnostics
            .iter()
            .find(|finding| finding.code == "config.unknown-key")
            .unwrap();
        assert_eq!(
            finding.path,
            format!("/decisionConnections/assessor/authorization/{branch}/unexpected")
        );
        let reported = serde_json::to_value(finding).unwrap();
        assert!(reported["source"]["line"].as_u64().unwrap() > 1);
        assert!(!reported.to_string().contains("private-canary"));
    }
    let mut d = document();
    d["decisionConnections"]["assessor"]["baseUrl"] = json!("${UNRESOLVED_DECISION_ENDPOINT}");
    d["decisionConnections"]["assessor"]["authorization"] = json!({"local":{}});
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(&d).unwrap()).unwrap();
    let checked = RuntimeConfig::check_file(&path, false);
    assert!(checked
        .diagnostics
        .iter()
        .all(|finding| finding.severity != registry_platform_yaml::Severity::Error));
    assert!(checked.defers("/decisionConnections/assessor/baseUrl"));
}
