// SPDX-License-Identifier: Apache-2.0
use std::{sync::Arc, time::Duration};

use registry_coordinator::{
    decision::{DecisionConfig, DecisionConnection},
    protocol::CallOutcome,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};
use wiremock::{
    matchers::{body_bytes, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn config(base: &str, protocol: &str) -> DecisionConfig {
    serde_json::from_value(json!({"protocol":protocol,"baseUrl":base,"model":"fixture-alias","authorization":{"local":{}}})).unwrap()
}

fn connection(config: &DecisionConfig) -> DecisionConnection {
    DecisionConnection::new(
        config,
        Arc::new(SecretResolver::new([SecretProvider::Environment], "").unwrap()),
    )
    .unwrap()
}

fn input() -> Value {
    json!({"state":{"ticket":"I was charged twice for my subscription this month."},"questions":{
        "team":{"type":"choice","instructions":"Which team should handle this ticket?","criteria":{
            "billing":"Charges, payments, refunds, subscriptions","technical":"Bugs, errors, things not working","other":"Anything else"}},
        "refund":{"type":"predicate","instructions":"Is the customer asking for money back?"},
        "urgency":{"type":"score","instructions":"How urgent is this ticket?","criteria":["Routine","Soon","Urgent"]}
    }})
}

// Published Ollama SystemOne example, with only the model alias changed:
// https://ollama.com/blog/ollama-now-supports-jev-style-decision-models
fn system_reply() -> Value {
    json!({"model":"fixture-resolved-model","answers":{
        "team":{"type":"choice","choice":"billing","probabilities":{"billing":0.985,"technical":0.012,"other":0.003},"confidence":0.922},
        "refund":{"type":"noul","noul":0.997},
        "urgency":{"type":"score","score":0.815,"legend":{"0":"Routine","1":"Soon","2":"Urgent"},"probabilities":{"0":0.378,"1":0.429,"2":0.193},"confidence":0.046}
    },"usage":{"input_tokens":841,"output_tokens":4}})
}

// Protocol-shaped local fixtures use the named fields documented by OpenAI.
// The refusal is deliberately returned before the other named answer.
fn openai_input() -> Value {
    json!({"state":["ticket",{"damaged":true}],"questions":{
        "damaged":{"type":"predicate","instructions":"Is the item damaged?"},
        "restricted":{"type":"predicate","instructions":"Evaluate the restricted question."},
        "severity":{"type":"score","instructions":"How severe is the issue?","criteria":["Cosmetic","Workaround available","Fully blocked"]},
        "team":{"type":"choice","instructions":"Select a department.","criteria":{"billing":"Billing issues","technical":"Technical issues"}}
    }})
}

fn openai_reply() -> Value {
    json!({"model":"fixture-resolved-model","answers":[
        {"type":"refusal","name":"restricted"},
        {"type":"choice","name":"team","choice":"billing","confidence":0.93,"probabilities":[{"value":"technical","probability":0.05},{"value":"billing","probability":0.95}]},
        {"type":"score","name":"severity","score":1.1,"confidence":0.55,"probabilities":[{"value":2,"label":"Fully blocked","probability":0.2},{"value":0,"label":"Cosmetic","probability":0.1},{"value":1,"label":"Workaround available","probability":0.7}]},
        {"type":"predicate","name":"damaged","probability":0.95}
    ],"usage":{"input_tokens":42,"input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0},"output_tokens":0,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":42}})
}

fn success(outcome: CallOutcome) -> Value {
    match outcome {
        CallOutcome::Success(value) => value,
        _ => panic!("expected a validated typed result"),
    }
}

#[test]
fn preparation_is_offline_exact_and_distinct_for_each_protocol() {
    let original = input();
    let mut cfg = config("http://127.0.0.1:9/prefix", "system-one");
    // A credential reference need not resolve during construction/preparation.
    cfg.authorization = serde_json::from_value(json!({"bearer":{"principal":"fixture-principal","tokenRef":"secret:env/COORDINATOR_DECISION_MISSING_FIXTURE_TOKEN"}})).unwrap();
    let bytes = connection(&cfg)
        .prepare(&original)
        .unwrap_or_else(|_| panic!("offline preparation"));
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        wire["questions"]["refund"],
        json!({"type":"noul","instructions":"Is the customer asking for money back?"})
    );
    assert_eq!(wire["state"], original["state"]);
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains("COORDINATOR_DECISION_MISSING"));

    let client = connection(&config("http://127.0.0.1:9", "openai-decisions"));
    let bytes = client
        .prepare(&original)
        .unwrap_or_else(|_| panic!("offline preparation"));
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        wire["input"],
        "{\"ticket\":\"I was charged twice for my subscription this month.\"}"
    );
    assert_eq!(wire["questions"][0]["name"], "refund");
    assert_eq!(
        wire["questions"][1]["choices"][0],
        json!({"value":"billing","description":"Charges, payments, refunds, subscriptions"})
    );
    assert_eq!(
        wire["questions"][2]["levels"],
        json!([{"label":"Routine"},{"label":"Soon"},{"label":"Urgent"}])
    );
    assert!(!wire.as_object().unwrap().contains_key("state"));
}

#[tokio::test]
async fn system_one_preserves_prefix_exact_preparation_and_native_statistics() {
    let server = MockServer::start().await;
    let client = connection(&config(&format!("{}/gateway/", server.uri()), "system-one"));
    let input = input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    Mock::given(method("POST"))
        .and(path("/gateway/v1/systemone"))
        .and(body_bytes(prepared.clone()))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(system_reply()))
        .expect(1)
        .mount(&server)
        .await;
    let value = success(client.call_prepared(&input, &prepared).await);
    assert_eq!(value["requestedModel"], "fixture-alias");
    assert_eq!(value["returnedModel"], "fixture-resolved-model");
    assert_eq!(
        value["answers"]["refund"],
        json!({"type":"predicate","probability":0.997})
    );
    assert_eq!(value["answers"]["urgency"]["score"], 0.815);
    assert_eq!(value["answers"]["urgency"]["nativeConfidence"], 0.046);
    assert_eq!(value["answers"]["team"]["choice"], "billing");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.contains_key("authorization"));
    assert!(!requests[0].headers.contains_key("idempotency-key"));
}

#[tokio::test]
async fn openai_matches_names_instead_of_positions_and_preserves_refusal() {
    let server = MockServer::start().await;
    let client = connection(&config(&server.uri(), "openai-decisions"));
    let input = openai_input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    Mock::given(method("POST"))
        .and(path("/v1/decisions"))
        .and(body_bytes(prepared.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply()))
        .expect(1)
        .mount(&server)
        .await;
    let value = success(client.call_prepared(&input, &prepared).await);
    assert_eq!(value["requestedModel"], "fixture-alias");
    assert_eq!(value["returnedModel"], "fixture-resolved-model");
    assert_eq!(value["usage"], openai_reply()["usage"]);
    assert_eq!(value["answers"]["restricted"], json!({"type":"refusal"}));
    assert_eq!(
        value["answers"]["damaged"],
        json!({"type":"predicate","probability":0.95})
    );
    assert_eq!(value["answers"]["severity"]["score"], 1.1);
    assert_eq!(value["answers"]["severity"]["nativeConfidence"], 0.55);
    assert_eq!(value["usage"]["total_tokens"], 42);
}

#[tokio::test]
async fn openai_requires_complete_response_metadata_before_advancing() {
    let server = MockServer::start().await;
    let client = connection(&config(&server.uri(), "openai-decisions"));
    let input = openai_input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    let mut cases = Vec::new();
    for pointer in [
        "/answers",
        "/model",
        "/usage",
        "/usage/input_tokens",
        "/usage/input_tokens_details",
        "/usage/input_tokens_details/cache_write_tokens",
        "/usage/input_tokens_details/cached_tokens",
        "/usage/output_tokens",
        "/usage/output_tokens_details",
        "/usage/output_tokens_details/reasoning_tokens",
        "/usage/total_tokens",
    ] {
        let mut missing = openai_reply();
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        missing
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(member);
        cases.push(missing);
        let mut null = openai_reply();
        *null.pointer_mut(pointer).unwrap() = Value::Null;
        cases.push(null);
    }
    for (pointer, value) in [
        ("/model", json!(true)),
        ("/model", json!(" ")),
        ("/usage", json!([])),
        ("/usage/input_tokens", json!(-1)),
        ("/usage/input_tokens_details/cached_tokens", json!(0.5)),
        ("/usage/output_tokens_details/reasoning_tokens", json!("0")),
        ("/usage/total_tokens", json!(false)),
    ] {
        let mut malformed = openai_reply();
        *malformed.pointer_mut(pointer).unwrap() = value;
        cases.push(malformed);
    }
    for response in cases {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-invalid-response")
        );
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn openai_rate_limit_hints_do_not_enable_replay_after_dispatch() {
    let server = MockServer::start().await;
    let client = connection(&config(&server.uri(), "openai-decisions"));
    let input = openai_input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    for (kind, code) in [
        ("rate_limit_error", "slow_down"),
        ("rate_limit_error", "rate_limit_exceeded"),
        ("insufficient_quota", "credit_balance_exhausted"),
        ("insufficient_quota", "organization_spend_limit_exceeded"),
        ("insufficient_quota", "project_spend_limit_exceeded"),
        ("insufficient_quota", "organization_usage_limit_exceeded"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/decisions"))
            .and(body_bytes(prepared.clone()))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "1")
                    .set_body_json(json!({"error":{"type":kind,"code":code}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-uncertain")
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn malformed_or_mismatched_accepted_results_hold_without_repeating() {
    let server = MockServer::start().await;
    let mut cases = Vec::new();
    for (protocol, input, reply) in [
        ("system-one", input(), system_reply()),
        ("openai-decisions", openai_input(), openai_reply()),
    ] {
        let mut missing = reply.clone();
        if protocol == "system-one" {
            missing["answers"].as_object_mut().unwrap().remove("refund");
        } else {
            missing["answers"].as_array_mut().unwrap().pop();
        }
        cases.push((protocol, input.clone(), missing));
        let mut invalid = reply.clone();
        if protocol == "system-one" {
            invalid["answers"]["refund"]["noul"] = json!(1.01);
        } else {
            invalid["answers"][3]["probability"] = json!(-0.1);
        }
        cases.push((protocol, input.clone(), invalid));
        let mut rubric = reply.clone();
        if protocol == "system-one" {
            rubric["answers"]["urgency"]["legend"]["1"] = json!("Changed");
        } else {
            rubric["answers"][2]["probabilities"][1]["label"] = json!("Changed");
        }
        cases.push((protocol, input.clone(), rubric));
        let mut score = reply.clone();
        if protocol == "system-one" {
            score["answers"]["urgency"]["score"] = json!(3);
        } else {
            score["answers"][2]["score"] = json!(3);
        }
        cases.push((protocol, input.clone(), score));
        let mut choice = reply.clone();
        if protocol == "system-one" {
            choice["answers"]["team"]["probabilities"]["unknown"] = json!(0.0);
        } else {
            choice["answers"][1]["probabilities"][0]["value"] = json!("billing");
        }
        cases.push((protocol, input.clone(), choice));
        let mut mass = reply.clone();
        if protocol == "system-one" {
            mass["answers"]["team"]["probabilities"]["billing"] = json!(0.1);
        } else {
            mass["answers"][1]["probabilities"][1]["probability"] = json!(0.1);
        }
        cases.push((protocol, input.clone(), mass));
        let mut confidence = reply.clone();
        if protocol == "system-one" {
            confidence["answers"]["team"]["confidence"] = json!(1.1);
        } else {
            confidence["answers"][1]["confidence"] = json!(1.1);
        }
        cases.push((protocol, input.clone(), confidence));
        let mut contradictory = reply.clone();
        if protocol == "system-one" {
            contradictory["answers"]["team"]["choice"] = json!("technical");
        } else {
            contradictory["answers"][1]["choice"] = json!("technical");
        }
        cases.push((protocol, input.clone(), contradictory));
        let mut mean = reply.clone();
        if protocol == "system-one" {
            mean["answers"]["urgency"]["score"] = json!(1.9);
        } else {
            mean["answers"][2]["score"] = json!(1.9);
        }
        cases.push((protocol, input.clone(), mean));
    }
    let mut duplicate = openai_reply();
    duplicate["answers"][3]["name"] = json!("restricted");
    cases.push(("openai-decisions", openai_input(), duplicate));
    for (protocol, input, response) in cases {
        let client = connection(&config(&server.uri(), protocol));
        let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-invalid-response")
        );
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn status_refusal_timeout_redirect_and_response_bounds_never_trigger_hidden_retry() {
    let server = MockServer::start().await;
    let input = input();
    for status in [400, 401, 403, 422, 429, 503, 307] {
        let client = connection(&config(&server.uri(), "system-one"));
        let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}/second", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = client.call_prepared(&input, &prepared).await;
        if [400, 401, 403, 422].contains(&status) {
            assert!(matches!(result, CallOutcome::Refused { code } if code == "decision-refused"));
        } else {
            assert!(
                matches!(result, CallOutcome::Uncertain { code } if code == "decision-uncertain")
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
        server.reset().await;
    }
    let mut cfg = config(&server.uri(), "system-one");
    cfg.attempt_timeout_milliseconds = registry_platform_yaml::BoundedU64::new(800).unwrap();
    let client = connection(&cfg);
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(system_reply())
                .set_delay(Duration::from_millis(2000)),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client.call_prepared(&input, &prepared).await,
        CallOutcome::Uncertain { .. }
    ));
    server.verify().await;
    server.reset().await;
    cfg.maximum_response_bytes = registry_platform_yaml::BoundedU64::new(40).unwrap();
    let client = connection(&cfg);
    for body in [
        serde_json::to_string(&system_reply()).unwrap(),
        "{\"answers\":{},\"answers\":{}}".into(),
    ] {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-invalid-response")
        );
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn invalid_input_or_changed_preparation_is_refused_before_network() {
    let server = MockServer::start().await;
    let mut cfg = config(&server.uri(), "system-one");
    let client = connection(&cfg);
    let original = input();
    let prepared = client
        .prepare(&original)
        .unwrap_or_else(|_| panic!("prepare"));
    let mut changed = original.clone();
    changed["state"] = json!("changed");
    assert!(matches!(
        client.call_prepared(&changed, &prepared).await,
        CallOutcome::Refused { .. }
    ));
    for invalid in [
        json!({"state":false,"questions":{}}),
        json!({"state":{},"questions":{"Bad":{"type":"predicate","instructions":"Check"}}}),
        json!({"state":{},"questions":{"score":{"type":"score","instructions":"Check","criteria":[]}}}),
        json!({"state":{},"questions":{"p":{"type":"predicate","instructions":"Check","extra":true}}}),
    ] {
        assert!(matches!(
            client.prepare(&invalid),
            Err(CallOutcome::Refused { .. })
        ));
    }
    cfg.maximum_request_bytes = registry_platform_yaml::BoundedU64::new(20).unwrap();
    assert!(matches!(
        connection(&cfg).prepare(&original),
        Err(CallOutcome::Refused { .. })
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn config_rejects_ambiguous_auth_and_unauthenticated_nonloopback() {
    for value in [
        json!({"local":{"extra":true}}),
        json!({"local":{},"bearer":{"tokenRef":"secret:env/TOKEN","principal":"service"}}),
        json!({"bearer":{"tokenRef":"secret:env/TOKEN","principal":"service","extra":true}}),
    ] {
        let mut raw = serde_json::to_value(config("http://127.0.0.1:9", "system-one")).unwrap();
        raw["authorization"] = value;
        assert!(serde_json::from_value::<DecisionConfig>(raw).is_err());
    }
    for url in [
        "https://decision.example.test",
        "http://localhost:1234",
        "http://192.168.1.2",
        "http://127.0.0.1:1234/?x=1",
    ] {
        assert!(config(url, "system-one").validate().is_err());
    }
    assert!(config("http://[::1]:11434", "system-one")
        .validate()
        .is_ok());
    let mut raw = serde_json::to_value(config("http://127.0.0.1:9", "system-one")).unwrap();
    raw["baseUrl"] = json!("http://user:password@127.0.0.1:1234");
    assert!(serde_json::from_value::<DecisionConfig>(raw).is_err());
}

#[tokio::test]
async fn accepted_media_types_and_duplicate_json_are_checked_before_results_escape() {
    let server = MockServer::start().await;
    let client = connection(&config(&server.uri(), "system-one"));
    let input = input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    for media in [
        None,
        Some("text/plain"),
        Some("application/json, text/plain"),
        Some("application/json; charset=latin1"),
    ] {
        let mut reply =
            ResponseTemplate::new(200).set_body_bytes(serde_json::to_vec(&system_reply()).unwrap());
        if let Some(media) = media {
            reply = reply.insert_header("content-type", media);
        }
        Mock::given(method("POST"))
            .respond_with(reply)
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-invalid-response")
        );
        server.verify().await;
        server.reset().await;
    }
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(serde_json::to_vec(&system_reply()).unwrap())
                .insert_header("content-type", "application/json; charset=utf-8"),
        )
        .expect(1)
        .mount(&server)
        .await;
    success(client.call_prepared(&input, &prepared).await);
    server.verify().await;
    server.reset().await;
    let duplicate = serde_json::to_string(&system_reply())
        .unwrap()
        .replace("\"noul\":0.997", "\"noul\":0.997,\"noul\":0.1");
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(duplicate)
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Uncertain { code } if code == "decision-invalid-response")
    );
}

#[tokio::test]
async fn bearer_secret_is_attempt_local_and_rotation_does_not_change_prepared_body() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let token_path = root.path().join("token");
    std::fs::write(&token_path, "synthetic-token-one").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut cfg = config(&server.uri(), "openai-decisions");
    cfg.authorization = serde_json::from_value(
        json!({"bearer":{"principal":"fixture-service","tokenRef":"secret:file/token"}}),
    )
    .unwrap();
    let client = DecisionConnection::new(
        &cfg,
        Arc::new(SecretResolver::new([SecretProvider::File], root.path()).unwrap()),
    )
    .unwrap();
    let input = openai_input();
    let prepared = client.prepare(&input).unwrap_or_else(|_| panic!("prepare"));
    assert!(!String::from_utf8(prepared.clone())
        .unwrap()
        .contains("synthetic-token"));
    for token in ["synthetic-token-one", "synthetic-token-two"] {
        std::fs::write(&token_path, token).unwrap();
        Mock::given(method("POST"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_bytes(prepared.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply()))
            .expect(1)
            .mount(&server)
            .await;
        let value = success(client.call_prepared(&input, &prepared).await);
        assert!(!value.to_string().contains(token));
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn missing_attempt_credential_is_proven_unsent_and_retryable() {
    let server = MockServer::start().await;
    let mut cfg = config(&server.uri(), "openai-decisions");
    cfg.authorization = serde_json::from_value(
        json!({"bearer":{"principal":"fixture","tokenRef":"secret:file/missing"}}),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let client = DecisionConnection::new(
        &cfg,
        Arc::new(SecretResolver::new([SecretProvider::File], root.path()).unwrap()),
    )
    .unwrap();
    let input = openai_input();
    let prepared = client
        .prepare(&input)
        .unwrap_or_else(|_| panic!("offline prepare"));
    assert!(
        matches!(client.call_prepared(&input, &prepared).await, CallOutcome::Retryable { code } if code == "decision-unavailable")
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
