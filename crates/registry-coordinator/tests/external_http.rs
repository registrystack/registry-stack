// SPDX-License-Identifier: Apache-2.0
use std::{sync::Arc, time::Duration};

use registry_coordinator::{
    external_http::{ExternalHttpConfig, ExternalHttpConnection},
    protocol::CallOutcome,
};
use registry_platform_httputil::client::{BearerToken, StaticToken, TokenError, TokenProvider};
use serde_json::json;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn config(base: &str) -> ExternalHttpConfig {
    serde_json::from_value(json!({
        "baseUrl":base,
        "paths":["offices"],
        "queryParameters":["district"],
        "responseSchema":{
            "type":"object", "required":["status","body"], "additionalProperties":false,
            "properties":{
                "status":{"type":"integer","minimum":100,"maximum":599},
                "body":{"anyOf":[{"type":"null"},{
                    "type":"object","required":["items"],"additionalProperties":false,
                    "properties":{"items":{"type":"array","maxItems":10,"items":{
                        "type":"object","required":["id"],"additionalProperties":false,
                        "properties":{"id":{"type":"string","maxLength":64}}
                    }}}
                }]}
            }
        }
    }))
    .unwrap()
}

fn connection(config: &ExternalHttpConfig) -> ExternalHttpConnection {
    ExternalHttpConnection::new(config, None).unwrap()
}

fn authorization() -> registry_coordinator::runtime::AuthorizationConfig {
    serde_json::from_value(json!({
        "tokenEndpoint":"http://127.0.0.1:9999/token", "clientId":"directory-reader",
        "signingKeyRef":"secret:file/directory-reader", "resource":"https://directory.example.test",
        "scopes":["directory.read"]
    }))
    .unwrap()
}

#[tokio::test]
async fn lookup_preserves_deployment_prefix_and_encodes_query_as_data() {
    let server = MockServer::start().await;
    for suffix in ["/directory/v2", "/directory/v2/"] {
        Mock::given(method("GET"))
            .and(path("/directory/v2/offices"))
            .and(query_param(
                "district",
                "north &south=http://elsewhere.test/?x=1",
            ))
            .and(header("accept", "application/json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"items":[{"id":"office-1"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let config = config(&format!("{}{suffix}", server.uri()));
        match connection(&config)
            .get(&json!({"path":"offices","query":{"district":"north &south=http://elsewhere.test/?x=1"}}))
            .await
        {
            CallOutcome::Success(reply) => assert_eq!(reply, json!({"status":200,"body":{"items":[{"id":"office-1"}]}})),
            _ => panic!("the configured read succeeds"),
        }
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn runtime_input_cannot_supply_destinations_headers_or_unreviewed_scope() {
    let server = MockServer::start().await;
    let connection = connection(&config(&server.uri()));
    for input in [
        json!({"path":"https://elsewhere.test/offices"}),
        json!({"path":"//elsewhere.test/offices"}),
        json!({"path":"../offices"}),
        json!({"path":"/offices"}),
        json!({"path":"offices?district=north"}),
        json!({"path":"offices","headers":{"authorization":"secret-canary"}}),
        json!({"path":"offices","method":"POST"}),
        json!({"path":"offices","baseUrl":"https://elsewhere.test"}),
        json!({"path":"offices","query":{"token":"secret-canary"}}),
        json!({"path":"offices","query":{"district":[]}}),
        json!({"path":"offices","query":{"district":"x".repeat(1025)}}),
    ] {
        assert!(matches!(connection.get(&input).await,
            CallOutcome::Refused { code } if code == "external-invalid-command"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn completed_http_statuses_remain_available_to_workflow_branches() {
    let server = MockServer::start().await;
    let connection = connection(&config(&server.uri()));
    for status in [200, 400, 404, 429, 500] {
        Mock::given(method("GET"))
            .and(path("/offices"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"items":[]})))
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(connection.get(&json!({"path":"offices"})).await,
            CallOutcome::Success(reply) if reply == json!({"status":status,"body":{"items":[]}})));
        server.verify().await;
        server.reset().await;
    }
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    assert!(matches!(connection.get(&json!({"path":"offices"})).await,
        CallOutcome::Success(reply) if reply == json!({"status":404,"body":null})));
}

#[tokio::test]
async fn redirects_do_not_follow_or_leak_a_configured_credential() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/offices"))
        .and(header("authorization", "Bearer synthetic-directory-token"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", target.uri()))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config(&server.uri());
    config.authorization = Some(authorization());
    let tokens = Arc::new(StaticToken::new("synthetic-directory-token").unwrap());
    let connection = ExternalHttpConnection::new(&config, Some(tokens)).unwrap();
    assert!(matches!(connection.get(&json!({"path":"offices"})).await,
        CallOutcome::Refused { code } if code == "external-redirect"));
    assert!(target.received_requests().await.unwrap().is_empty());
    server.verify().await;
}

#[tokio::test]
async fn invalid_shape_duplicate_json_and_large_bodies_are_not_released() {
    let server = MockServer::start().await;
    let mut config = config(&server.uri());
    config.maximum_response_bytes = 128.try_into().unwrap();
    let connection = connection(&config);
    for response in [
        ResponseTemplate::new(200).set_body_string("not-json-sensitive-canary"),
        ResponseTemplate::new(200).set_body_string(r#"{"items":[],"items":[{"id":"different"}]}"#),
        ResponseTemplate::new(200).set_body_json(json!({"items":[{"id":7}]})),
        ResponseTemplate::new(200)
            .set_body_json(json!({"items":[],"sensitiveCanary":"must-not-release"})),
        ResponseTemplate::new(200).set_body_string("x".repeat(129)),
    ] {
        Mock::given(method("GET"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(connection.get(&json!({"path":"offices"})).await,
            CallOutcome::Refused { code } if code == "external-invalid-response"));
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn one_attempt_has_a_bounded_deadline_and_no_internal_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"items":[]}))
                .set_delay(Duration::from_secs(10)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config(&server.uri());
    config.attempt_timeout_milliseconds = 2000.try_into().unwrap();
    let connection = connection(&config);
    let started = std::time::Instant::now();
    assert!(matches!(connection.get(&json!({"path":"offices"})).await,
        CallOutcome::Retryable { code } if code == "external-unavailable"));
    // Allow scheduler contention in the parallel suite while proving the
    // ten-second receiver delay is cancelled by the attempt deadline.
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

struct SlowTokens;

#[async_trait::async_trait]
impl TokenProvider for SlowTokens {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        BearerToken::new("synthetic-token")
    }
}

#[tokio::test]
async fn the_attempt_deadline_includes_credential_acquisition() {
    let server = MockServer::start().await;
    let mut config = config(&server.uri());
    config.authorization = Some(authorization());
    config.attempt_timeout_milliseconds = 80.try_into().unwrap();
    let connection = ExternalHttpConnection::new(&config, Some(Arc::new(SlowTokens))).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(connection.get(&json!({"path":"offices"})).await,
        CallOutcome::Retryable { code } if code == "external-unavailable"));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn streamed_bodies_are_bounded_without_a_content_length_header() {
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n81\r\n{}\r\n0\r\n\r\n",
            "x".repeat(129)
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    let mut config = config(&format!("http://{address}"));
    config.maximum_response_bytes = 128.try_into().unwrap();
    assert!(
        matches!(connection(&config).get(&json!({"path":"offices"})).await,
        CallOutcome::Refused { code } if code == "external-invalid-response")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn metadata_targets_are_refused_before_acquiring_credentials() {
    let mut config = config("https://169.254.169.254");
    config.authorization = Some(authorization());
    let connection = ExternalHttpConnection::new(&config, Some(Arc::new(SlowTokens))).unwrap();
    assert!(matches!(connection.get(&json!({"path":"offices"})).await,
        CallOutcome::Refused { code } if code == "external-destination-refused"));
}

#[cfg(feature = "schema")]
#[test]
fn external_config_schema_declares_safe_defaults_and_bounded_sets() {
    let schema = serde_json::to_value(schemars::schema_for!(ExternalHttpConfig)).unwrap();
    assert_eq!(
        schema["properties"]["attemptTimeoutMilliseconds"]["default"],
        2000
    );
    assert_eq!(
        schema["properties"]["maximumResponseBytes"]["default"],
        65536
    );
    assert_eq!(schema["properties"]["paths"]["uniqueItems"], true);
    assert_eq!(
        schema["properties"]["responseSchema"]["x-registry-foreign"],
        "json-schema-2020-12"
    );
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let original = serde_json::to_value(config("https://directory.example.test")).unwrap();
    assert!(validator.is_valid(&original));
    for (field, value) in [
        ("attemptTimeoutMilliseconds", json!(0)),
        ("attemptTimeoutMilliseconds", json!(2001)),
        ("maximumResponseBytes", json!(0)),
        ("maximumResponseBytes", json!(65537)),
        ("paths", json!([])),
        ("baseUrl", json!("https://directory.example.test\n")),
        ("baseUrl", json!("https://directory.example.test\\offices")),
    ] {
        let mut document = original.clone();
        document[field] = value;
        assert!(!validator.is_valid(&document));
        assert!(serde_json::from_value::<ExternalHttpConfig>(document)
            .map_or(true, |config| config.validate().is_err()));
    }
}

#[test]
fn offline_contract_refuses_unsafe_urls_paths_and_external_schema_fetches() {
    let original = config("https://directory.example.test/institution");
    original.validate().unwrap();
    for base in [
        "http://10.0.0.1/",
        "http://localhost/",
        "https://user:secret@directory.example.test/",
        "https://directory.example.test/?token=secret",
        "https://directory.example.test/#fragment",
    ] {
        let mut config = original.clone();
        config.base_url = base.parse().unwrap();
        assert!(config.validate().is_err());
    }
    for path in [
        "../offices",
        "/offices",
        "offices?district=north",
        "offices//north",
        "offices\\north",
    ] {
        let mut config = original.clone();
        config.paths =
            registry_platform_yaml::UniqueList::new(vec![path.parse().unwrap()]).unwrap();
        assert!(config.validate().is_err());
    }
    let mut config = original.clone();
    config.response_schema =
        registry_platform_yaml::ForeignValue(json!({"$ref":"https://schemas.example.test/read"}));
    assert!(config.validate().is_err());
    for field in ["paths", "queryParameters"] {
        let mut document = serde_json::to_value(&original).unwrap();
        let first = document[field][0].clone();
        document[field] = json!([first, first]);
        assert!(serde_json::from_value::<ExternalHttpConfig>(document).is_err());
    }
    for base in [
        " https://directory.example.test",
        "https://directory.example.test\n",
        "https://directory.example.test\\offices",
    ] {
        let mut document = serde_json::to_value(&original).unwrap();
        document["baseUrl"] = json!(base);
        assert!(serde_json::from_value::<ExternalHttpConfig>(document).is_err());
    }
    assert!(ExternalHttpConnection::new(
        &original,
        Some(Arc::new(StaticToken::new("synthetic-token").unwrap()))
    )
    .is_err());
    let mut private = original.clone();
    private.authorization = Some(authorization());
    assert!(ExternalHttpConnection::new(&private, None).is_err());
    private.authorization.as_mut().unwrap().resource = "sensitive-invalid-resource-canary".into();
    let error = private.validate().unwrap_err();
    assert!(!error
        .to_string()
        .contains("sensitive-invalid-resource-canary"));
}
