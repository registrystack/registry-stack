// SPDX-License-Identifier: Apache-2.0
//! Real runtime-reader and adapter coverage for configured external reads.
use registry_coordinator::{
    adapters::HttpAdapters,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    runtime::{RuntimeConfig, API_VERSION, KIND},
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn document() -> Value {
    json!({
        "apiVersion":API_VERSION,"kind":KIND,
        "secretProviders":{"environment":{}},
        "database":{
            "runtimeUrlRef":"secret:env/COORDINATOR_EXTERNAL_TEST_UNRESOLVED_DATABASE",
            "migrationUrlRef":"secret:env/COORDINATOR_EXTERNAL_TEST_UNRESOLVED_DATABASE"
        },
        "namespace":"coordinator_external_test",
        "externalHttpConnections":{
            "office-directory":{
                "baseUrl":"https://directory.example.test/tenant/v2",
                "paths":["offices","districts"],
                "queryParameters":["district","language"],
                "responseSchema":{
                    "type":"object","required":["status","body"],"additionalProperties":false,
                    "properties":{
                        "status":{"type":"integer","minimum":100,"maximum":599},
                        "body":{"type":"object","required":["items"],"additionalProperties":false,
                            "properties":{"items":{"type":"array","maxItems":10,"items":{
                                "type":"object","required":["id"],"additionalProperties":false,
                                "properties":{"id":{"type":"string","maxLength":64}}
                            }}}
                        }
                    }
                }
            }
        }
    })
}

fn authorization() -> Value {
    json!({
        "tokenEndpoint":"https://issuer.example.test/token", "clientId":"directory-reader",
        "signingKeyRef":"secret:file/directory-reader", "resource":"urn:example:directory",
        "scopes":["directory:read","districts:read"]
    })
}

fn task_authority() -> Value {
    json!({"baseUrl":"https://casework.example.test", "issuer":"https://issuer.example.test",
        "subject":"directory-reader", "exchangeAudience":"urn:example:exchange",
        "bootstrapResource":"urn:example:casework"})
}

fn protected_document() -> Value {
    let mut document = document();
    // Deliberately missing: offline validation never opens a root or resolves
    // an unprovided signing key or database connection value.
    document["secretProviders"]["file"] =
        json!({"root":"/private/tmp/coordinator-external-unresolved-secrets"});
    document["externalHttpConnections"]["office-directory"]["authorization"] = authorization();
    document
}

fn load(document: &Value) -> registry_coordinator::Result<RuntimeConfig> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    RuntimeConfig::load(&path)
}

#[test]
fn external_only_runtime_loads_and_offline_check_never_resolves_secrets() {
    let document = document();
    let config = load(&document).unwrap();
    assert!(config.connections.is_empty());
    assert_eq!(config.external_http_connections.len(), 1);
    let effective = config.document().unwrap();
    assert!(effective.get("connections").is_none());
    assert_eq!(
        effective["externalHttpConnections"]["office-directory"]["attemptTimeoutMilliseconds"],
        2000
    );
    assert_eq!(
        effective["externalHttpConnections"]["office-directory"]["maximumResponseBytes"],
        65536
    );

    let protected = protected_document();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, serde_json::to_vec(&protected).unwrap()).unwrap();
    let checked = RuntimeConfig::check_file(&path, true);
    assert!(!checked.unavailable);
    assert!(checked.diagnostics.is_empty());
    checked.loaded.unwrap().config.binding_digest().unwrap();
}

#[test]
fn missing_authorization_providers_and_cross_kind_name_collisions_are_refused() {
    let original = protected_document();
    for invalid in [
        {
            let mut d = original.clone();
            d["secretProviders"].as_object_mut().unwrap().remove("file");
            d
        },
        {
            let mut d = original.clone();
            d["externalHttpConnections"]["office-directory"]["authorization"]["signingKeyRef"] =
                json!("secret:env/EXTERNAL_TEST_UNRESOLVED_KEY");
            d
        },
    ] {
        let error = load(&invalid)
            .err()
            .expect("an incompatible key provider is refused");
        assert!(error.field.as_deref().unwrap().contains("signingKeyRef"));
        assert!(!error.to_string().contains("EXTERNAL_TEST_UNRESOLVED_KEY"));
    }
    let mut collision = original.clone();
    collision["connections"] = json!({"office-directory":{
        "product":"messaging", "baseUrl":"https://messaging.example.test", "authorization":authorization()
    }});
    let error = load(&collision)
        .err()
        .expect("connection names have one namespace");
    assert_eq!(
        error.field.as_deref(),
        Some("/externalHttpConnections/office-directory")
    );
    let mut empty = document();
    empty
        .as_object_mut()
        .unwrap()
        .remove("externalHttpConnections");
    assert!(load(&empty).is_err());
    let mut unsupported_authority = original;
    unsupported_authority["externalHttpConnections"]["office-directory"]["authorization"]
        ["taskAuthority"] = task_authority();
    let error = load(&unsupported_authority)
        .err()
        .expect("external reads cannot acquire task mutation authority");
    assert!(error.field.as_deref().unwrap().contains("taskAuthority"));
}

#[test]
fn semantic_binding_digest_survives_secret_rotation_and_set_reordering() {
    let original = protected_document();
    let digest = load(&original).unwrap().binding_digest().unwrap();
    let mut equivalent = original.clone();
    let binding = &mut equivalent["externalHttpConnections"]["office-directory"];
    binding["paths"] = json!(["districts", "offices"]);
    binding["queryParameters"] = json!(["language", "district"]);
    binding["authorization"]["scopes"] = json!(["districts:read", "directory:read"]);
    binding["authorization"]["signingKeyRef"] = json!("secret:file/rotated-directory-reader");
    binding["authorization"]["clientAssertionAudience"] =
        binding["authorization"]["tokenEndpoint"].clone();
    assert_eq!(load(&equivalent).unwrap().binding_digest().unwrap(), digest);

    for (member, value) in [
        ("baseUrl", json!("https://directory.example.test/tenant/v3")),
        ("paths", json!(["offices"])),
        ("queryParameters", json!(["district"])),
        (
            "responseSchema",
            json!({"type":"object","required":["differentReply"]}),
        ),
        ("attemptTimeoutMilliseconds", json!(1000)),
        ("maximumResponseBytes", json!(8192)),
    ] {
        let mut changed = original.clone();
        changed["externalHttpConnections"]["office-directory"][member] = value;
        assert_ne!(
            load(&changed).unwrap().binding_digest().unwrap(),
            digest,
            "{member} changes the reviewed call interpretation"
        );
    }
    let mut changed_principal = original.clone();
    changed_principal["externalHttpConnections"]["office-directory"]["authorization"]["clientId"] =
        json!("another-reader");
    assert_ne!(
        load(&changed_principal).unwrap().binding_digest().unwrap(),
        digest
    );
    let mut invalid_schema = original;
    invalid_schema["externalHttpConnections"]["office-directory"]["responseSchema"] =
        json!({"$ref":"https://schemas.example.test/read"});
    assert!(load(&invalid_schema).is_err());
}

#[cfg(feature = "schema")]
#[test]
fn external_only_runtime_schema_matches_reader_for_defaults_and_closed_scope() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let original = document();
    assert!(validator.is_valid(&original));
    assert!(validator.is_valid(&protected_document()));
    assert!(validator.is_valid(&load(&original).unwrap().document().unwrap()));
    for (member, value) in [
        ("attemptTimeoutMilliseconds", json!(2001)),
        ("maximumResponseBytes", json!(65537)),
        ("paths", json!([])),
        ("paths", json!(["offices", "offices"])),
        ("authorization", Value::Null),
        ("baseUrl", json!("https://directory.example.test\n")),
    ] {
        let mut invalid = original.clone();
        invalid["externalHttpConnections"]["office-directory"][member] = value;
        assert!(!validator.is_valid(&invalid), "schema refuses {member}");
        assert!(load(&invalid).is_err(), "reader refuses {member}");
    }
    let mut empty = original;
    empty
        .as_object_mut()
        .unwrap()
        .remove("externalHttpConnections");
    assert!(!validator.is_valid(&empty));
    let mut unsupported_authority = protected_document();
    unsupported_authority["externalHttpConnections"]["office-directory"]["authorization"]
        ["taskAuthority"] = task_authority();
    assert!(!validator.is_valid(&unsupported_authority));
}

#[tokio::test]
async fn configured_logical_get_reaches_the_real_adapter_and_checks_response_shape() {
    let server = MockServer::start().await;
    let mut document = document();
    document["externalHttpConnections"]["office-directory"]["baseUrl"] =
        json!(format!("{}/tenant/v2", server.uri()));
    let config = load(&document).unwrap();
    let adapters = HttpAdapters::new(&config).unwrap();
    let request = CallRequest {
        connection: "office-directory".into(),
        operation: Operation::ExternalGet,
        input: json!({"path":"offices","query":{"district":"north"}}),
        idempotency_key: None,
    };
    Mock::given(method("GET"))
        .and(path("/tenant/v2/offices"))
        .and(query_param("district", "north"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"items":[{"id":"office-1"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(adapters.call(&request).await,
        CallOutcome::Success(reply) if reply == json!({"status":200,"body":{"items":[{"id":"office-1"}]}})));
    server.verify().await;
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[{"id":7}]})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(adapters.call(&request).await,
        CallOutcome::Refused { code } if code == "external-invalid-response"));
    server.verify().await;
    assert_eq!(adapters.binding_digest(), config.binding_digest().unwrap());
}
