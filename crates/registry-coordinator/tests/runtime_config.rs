// SPDX-License-Identifier: Apache-2.0
use registry_coordinator::{
    definition::Definition,
    project,
    runtime::{RuntimeConfig, API_VERSION, KIND},
};
use serde_json::{json, Value};
use std::fs;

const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml");
const CANARY: &str = "secret-config-value-never-print";
const SCHEDULING_RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/deferred-appointment/runtime.yaml");
const REVIEW_RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/reviewed-notice/runtime.yaml");

fn yaml_value(text: &str) -> std::result::Result<Value, registry_platform_yaml::Report> {
    document_value(text, API_VERSION, KIND)
}
fn document_value(
    text: &str,
    api_version: &str,
    kind: &str,
) -> std::result::Result<Value, registry_platform_yaml::Report> {
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
    let versions = [ApiVersion::current(api_version)];
    let format = FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &versions,
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    Reader::new("fixture.yaml")
        .read(text.as_bytes(), &Expect::one(&format))
        .map(|document| document.to_json_value())
}

fn load(text: &str) -> registry_coordinator::Result<RuntimeConfig> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    fs::write(&path, text).unwrap();
    RuntimeConfig::load(&path)
}
fn refused(text: &str) -> registry_coordinator::CoordinatorError {
    match load(text) {
        Ok(_) => panic!("configuration must refuse"),
        Err(error) => error,
    }
}

fn state_key_versions(active: u32, versions: &[&str]) -> Value {
    let mut document: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    document["deployment"]["activeStateKey"] = json!(active);
    document["deployment"]["stateKeys"] = Value::Object(
        versions
            .iter()
            .map(|version| {
                (
                    (*version).to_owned(),
                    json!({"keyRef":"secret:file/state-key"}),
                )
            })
            .collect(),
    );
    document
}

#[test]
fn removed_jwks_tag_names_the_shared_type_replacement_without_values() {
    let mut document = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let jwks = document["deployment"]["authentication"]["jwksSource"]
        .as_object_mut()
        .unwrap();
    jwks.remove("type");
    jwks.insert("kind".into(), json!(CANARY));
    let error = refused(&document.to_string());
    let removed = error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "config.removed-key")
        .expect("the removed member names its replacement beside the missing type");
    assert_eq!(removed.path, "/deployment/authentication/jwksSource/kind");
    assert!(removed
        .suggested_action
        .contains("deployment.authentication.jwksSource.type"));
    assert!(!error.to_string().contains(CANARY));
    assert!(removed.source.as_ref().unwrap().line.is_some());
}

#[test]
fn policy_keys_are_the_only_closed_client_admission_configuration() {
    let original = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let config = load(&original.to_string()).unwrap();
    let access = &config.deployment.as_ref().unwrap().authentication;
    assert!(access.policies.contains_key("institution-producer"));
    assert!(access.policies.contains_key("institution-operator"));
    let roundtrip = config.document().unwrap();
    assert!(roundtrip["deployment"]["authentication"]
        .get("allowedClients")
        .is_none());
    #[cfg(feature = "schema")]
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    #[cfg(feature = "schema")]
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    for value in [json!({}), json!([]), json!("unrestricted"), Value::Null] {
        let mut document = original.clone();
        document["deployment"]["authentication"]["policies"] = value;
        assert!(load(&document.to_string()).is_err());
        #[cfg(feature = "schema")]
        assert!(!validator.is_valid(&document));
    }
    let mut legacy = original.clone();
    legacy["deployment"]["authentication"]["allowedClients"] = json!(["institution-producer"]);
    let error = refused(&legacy.to_string());
    assert_eq!(
        error.field.as_deref(),
        Some("/deployment/authentication/allowedClients")
    );
    #[cfg(feature = "schema")]
    assert!(!validator.is_valid(&legacy));
    let mut duplicated = original;
    duplicated["deployment"]["authentication"]["policies"]["institution-producer"]["clientId"] =
        json!(CANARY);
    let error = refused(&duplicated.to_string());
    assert_eq!(
        error.field.as_deref(),
        Some("/deployment/authentication/policies/institution-producer/clientId")
    );
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn exact_client_keys_keep_external_identity_grammar_and_source_addressing() {
    let mut document = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let policies = document["deployment"]["authentication"]["policies"]
        .as_object_mut()
        .unwrap();
    let policy = policies.remove("institution-producer").unwrap();
    policies.insert("urn:client:institution.v1/producer~primary".into(), policy);
    let config = load(&document.to_string()).unwrap();
    assert!(config
        .deployment
        .as_ref()
        .unwrap()
        .authentication
        .policies
        .contains_key("urn:client:institution.v1/producer~primary"));
    document["deployment"]["authentication"]["policies"]
        ["urn:client:institution.v1/producer~primary"]["workflows"] = json!(["invalid.workflow"]);
    let error = refused(&document.to_string());
    let pointer = "/deployment/authentication/policies/urn:client:institution.v1~1producer~0primary/workflows";
    assert_eq!(error.field.as_deref(), Some(pointer));
    let diagnostic = error
        .diagnostics
        .iter()
        .find(|d| d.path == pointer)
        .unwrap();
    assert!(diagnostic.source.as_ref().unwrap().line.is_some());
    let duplicate = SCHEDULING_RUNTIME.replace("      institution-producer:", "      institution-producer:\n        requiredScopes: [coordinator:start]\n        workflows: [deferred-appointment]\n        actions: [start, status]\n      institution-producer:");
    assert_eq!(refused(&duplicate).code, "yaml.duplicate-key");
}

#[test]
fn state_key_versions_refuse_zero_before_resolving_secrets() {
    for (active, versions) in [(0, vec!["0"]), (1, vec!["0", "1"])] {
        let error = refused(&state_key_versions(active, &versions).to_string());
        if active == 0 {
            assert_eq!(error.code, "config.out-of-range");
            assert_eq!(error.field.as_deref(), Some("/deployment/activeStateKey"));
        } else {
            assert_eq!(error.code, "coordinator.deployment.configuration");
            assert!(error
                .suggested_action
                .as_deref()
                .unwrap()
                .contains("nonzero"));
        }
    }
    for (active, versions) in [(1, vec!["1"]), (u32::MAX, vec!["1", "4294967295"])] {
        load(&state_key_versions(active, &versions).to_string()).unwrap();
    }
}

#[test]
fn state_keys_keep_nested_reference_shape_and_internal_versions() {
    let document = state_key_versions(1, &["1"]);
    let config = load(&document.to_string()).unwrap();
    assert_eq!(
        config.deployment.as_ref().unwrap().state_keys["1"].as_str(),
        "secret:file/state-key"
    );
    assert_eq!(
        config.document().unwrap()["deployment"]["stateKeys"],
        document["deployment"]["stateKeys"]
    );
    for value in [
        json!({"1":"secret:file/state-key"}),
        json!({"1":{"keyRef":null}}),
        json!({"1":{"keyRef":"secret:file/state-key","ignored":true}}),
    ] {
        let mut wrong = document.clone();
        wrong["deployment"]["stateKeys"] = value;
        assert!(load(&wrong.to_string()).is_err());
    }
}

#[cfg(feature = "schema")]
#[test]
fn state_key_versions_schema_refuses_active_and_retained_zero() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    for (active, versions) in [(0, vec!["0"]), (1, vec!["0", "1"])] {
        assert!(!validator.is_valid(&state_key_versions(active, &versions)));
    }
    for (active, versions) in [(1, vec!["1"]), (u32::MAX, vec!["1", "4294967295"])] {
        assert!(validator.is_valid(&state_key_versions(active, &versions)));
    }
}

#[test]
fn scope_lists_match_the_provider_constructor_offline() {
    for observation in [false, true] {
        let original: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
        let member = if observation {
            "observationAuthorization"
        } else {
            "authorization"
        };
        let field = if observation {
            "/connections/bookings/observationAuthorization/scopes"
        } else {
            "/connections/bookings/authorization/scopes"
        };
        for (scopes, reason) in [
            (
                vec![CANARY.to_owned(), CANARY.to_owned()],
                "must not repeat a value",
            ),
            (
                (0..33).map(|i| format!("scope:{i}")).collect(),
                "at most 32 values",
            ),
            (vec!["a".repeat(257)], "1..=256 byte RFC 6749 scope-tokens"),
        ] {
            let mut document = original.clone();
            document["connections"]["bookings"][member]["scopes"] = json!(scopes);
            let error = refused(&document.to_string());
            if reason == "must not repeat a value" {
                assert_eq!(error.code, "config.duplicate-item");
                assert!(error.field.as_deref().unwrap().starts_with(field));
                assert!(!error.suggested_action.as_deref().unwrap().is_empty());
            } else {
                assert_eq!(error.code, "coordinator.runtime-config.refused");
                assert_eq!(error.field.as_deref(), Some(field));
                assert!(error.suggested_action.as_deref().unwrap().contains(reason));
            }
            assert!(!error.to_string().contains(CANARY));
        }
        for scopes in [
            (0..32).map(|i| format!("scope:{i}")).collect::<Vec<_>>(),
            vec!["a".repeat(256)],
            // Sixteen distinct tokens plus separators exactly fill the wire bound.
            (0..16)
                .map(|i| format!("{i:x}{}", "a".repeat(if i == 15 { 255 } else { 254 })))
                .collect(),
        ] {
            let mut document = original.clone();
            document["connections"]["bookings"][member]["scopes"] = json!(scopes);
            assert!(load(&document.to_string()).is_ok());
        }
    }
}

#[test]
fn breg_profiles_match_the_record_options_constructor_offline() {
    let original: Value = yaml_value(RUNTIME).unwrap();
    for profile in [
        CANARY.to_uppercase(),
        "a".repeat(129),
        "9reader".into(),
        "reader/control".into(),
    ] {
        let mut document = original.clone();
        document["connections"]["applications"]["profile"] = json!(profile);
        let error = refused(&document.to_string());
        assert_eq!(
            error.field.as_deref(),
            Some("/connections/applications/profile")
        );
        assert!(!error.to_string().contains(CANARY));
    }
    for profile in ["a".repeat(128), "_reader-1.2".into()] {
        let mut document = original.clone();
        document["connections"]["applications"]["profile"] = json!(profile);
        assert!(load(&document.to_string()).is_ok());
    }
}

#[test]
fn service_base_paths_match_clients_without_restricting_token_endpoints() {
    let original: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    for task in [false, true] {
        let mut document = original.clone();
        let binding = &mut document["connections"]["bookings"];
        let base = if task {
            &mut binding["authorization"]["taskAuthority"]["baseUrl"]
        } else {
            &mut binding["baseUrl"]
        };
        *base = json!("https://example.invalid/api//v1");
        let error = refused(&document.to_string());
        assert_eq!(
            error.field.as_deref(),
            Some(if task {
                "/connections/bookings/authorization/taskAuthority/baseUrl"
            } else {
                "/connections/bookings/baseUrl"
            })
        );
        let binding = &mut document["connections"]["bookings"];
        let base = if task {
            &mut binding["authorization"]["taskAuthority"]["baseUrl"]
        } else {
            &mut binding["baseUrl"]
        };
        *base = json!("https://example.invalid/api/v1/");
        binding["authorization"]["tokenEndpoint"] = json!("https://example.invalid/api//token");
        binding["observationAuthorization"]["tokenEndpoint"] =
            json!("https://example.invalid/api//token");
        assert!(load(&document.to_string()).is_ok());
    }
}

#[test]
fn runtime_secret_references_refuse_environment_substitution() {
    let error = refused(&RUNTIME.replace("secret:file/client-key", &format!("${{{CANARY}}}")));
    assert_eq!(error.code, "config.substitution-not-allowed");
    assert!(error.field.as_deref().unwrap().ends_with("signingKeyRef"));
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn runtime_loader_checks_envelope_unknown_duplicate_and_tagged_fields() {
    for (index, text) in [
        RUNTIME.replace(API_VERSION, "wrong"),
        RUNTIME.replace(KIND, "wrong"),
        RUNTIME.replace(
            "namespace: coordinator_demo",
            "namespace: coordinator_demo\nnamespace: coordinator_other",
        ),
        RUNTIME.replace(
            "namespace: coordinator_demo",
            "namespace: !tag coordinator_demo",
        ),
        RUNTIME.replace(
            "namespace: coordinator_demo",
            "namespace: coordinator_demo\nunknown: true",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(load(&text).is_err(), "refusal case {index}");
    }
}

#[test]
fn runtime_fields_and_binding_errors_name_the_fix_without_values() {
    let error =
        refused(&RUNTIME.replace("http://127.0.0.1:8100", &format!("http://{CANARY}.invalid")));
    assert_eq!(
        error.field.as_deref(),
        Some("/connections/applications/baseUrl")
    );
    assert!(!error.to_string().contains(CANARY));
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("loopback"));
    let config = load(&RUNTIME.replace("  applications:\n", "  wrong-name:\n")).unwrap();
    let root = tempfile::tempdir().unwrap();
    project::init(&root.path().join("flow"), None).unwrap();
    let definition = Definition::load(&root.path().join("flow")).unwrap();
    let error = config.validate_workflow(&definition.workflow).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("/connections/applications"));
}

#[test]
fn runtime_authorization_syntax_is_checked_offline_without_values() {
    let original: Value = yaml_value(RUNTIME).unwrap();
    for (member, value, field) in [
        ("resource", json!(format!("invalid {CANARY}")), "resource"),
        ("scopes", json!([]), "scopes"),
        ("scopes", json!([format!("invalid {CANARY}")]), "scopes[0]"),
        ("clientId", json!("  "), "clientId"),
        (
            "clientAssertionAudience",
            json!("  "),
            "clientAssertionAudience",
        ),
        (
            "clientAssertionAudience",
            json!(format!("urn:example:audience#{CANARY}")),
            "clientAssertionAudience",
        ),
        (
            "taskAuthority",
            json!({"baseUrl":"http://127.0.0.1:8200","issuer":"https://casework.local.example",
            "subject":"synthetic-agent","exchangeAudience":"urn:example:applications", "bootstrapResource":format!("invalid {CANARY}")}),
            "taskAuthority.bootstrapResource",
        ),
    ] {
        let mut document = original.clone();
        document["connections"]["applications"]["authorization"][member] = value;
        let error = refused(&serde_norway::to_string(&document).unwrap());
        assert_eq!(
            error.field.as_deref(),
            Some(
                format!(
                    "/connections/applications/authorization/{}",
                    field.replace(['.', '['], "/").replace(']', "")
                )
                .as_str()
            )
        );
        assert!(!error.to_string().contains(CANARY));
        assert!(error.suggested_action.is_some());
    }
}

#[test]
fn task_authority_control_characters_are_refused_offline_without_values() {
    let scheduling: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    for (runtime, connection) in [(RUNTIME, "applications"), (SCHEDULING_RUNTIME, "bookings")] {
        let mut original: Value = yaml_value(runtime).unwrap();
        original["connections"][connection]["authorization"]["taskAuthority"] =
            scheduling["connections"]["bookings"]["authorization"]["taskAuthority"].clone();
        for control in ['\n', '\0', '\u{7f}', '\u{85}', '\u{9f}'] {
            let mut document = original.clone();
            document["connections"][connection]["authorization"]["taskAuthority"]["subject"] =
                json!(format!("agent{control}{CANARY}"));
            let error = refused(&serde_norway::to_string(&document).unwrap());
            assert!(matches!(
                error.code.as_str(),
                "config.invalid-value" | "yaml.control-character"
            ));
            if error.code == "config.invalid-value" {
                assert_eq!(
                    error.field.as_deref(),
                    Some(
                        format!("/connections/{connection}/authorization/taskAuthority/subject")
                            .as_str()
                    )
                );
            } else {
                let source = error.diagnostics[0].source.as_ref().unwrap();
                assert!(source.line.is_some() && source.column.is_some());
            }
            assert!(!error.to_string().contains(CANARY));
            assert!(error.suggested_action.is_some());
        }
        // Shared exchange context permits non-control Unicode identity text.
        original["connections"][connection]["authorization"]["taskAuthority"]["subject"] =
            json!("agent-日本語");
        load(&serde_norway::to_string(&original).unwrap()).unwrap();
    }
}

#[test]
fn task_bound_scheduling_requires_non_task_observation_authorization_offline() {
    let original: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    load(SCHEDULING_RUNTIME).unwrap();
    let mut missing = original.clone();
    missing["connections"]["bookings"]
        .as_object_mut()
        .unwrap()
        .remove("observationAuthorization");
    let error = refused(&serde_norway::to_string(&missing).unwrap());
    assert_eq!(
        error.field.as_deref(),
        Some("/connections/bookings/observationAuthorization")
    );
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("original grant expires"));
    for (member, value) in [
        (
            "taskAuthority",
            original["connections"]["bookings"]["authorization"]["taskAuthority"].clone(),
        ),
        ("clientId", json!(CANARY)),
        ("resource", json!("urn:example:different-resource")),
        ("tokenEndpoint", json!("https://other-issuer.example/token")),
        ("scopes", json!([])),
    ] {
        let mut document = original.clone();
        document["connections"]["bookings"]["observationAuthorization"][member] = value;
        let error = refused(&serde_norway::to_string(&document).unwrap());
        assert_eq!(
            error.field.as_deref(),
            Some(if member == "scopes" {
                "/connections/bookings/observationAuthorization/scopes"
            } else {
                "/connections/bookings/observationAuthorization"
            })
        );
        assert!(!error.to_string().contains(CANARY));
    }
    // Catalogue reads remain valid without any task or observation authority.
    missing["connections"]["bookings"]["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("taskAuthority");
    load(&serde_norway::to_string(&missing).unwrap()).unwrap();
}

#[test]
fn ignored_observation_authority_is_refused_for_other_connection_modes() {
    let scheduling: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let mut ordinary_scheduling = scheduling.clone();
    ordinary_scheduling["connections"]["bookings"]["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("taskAuthority");
    let mut cases = vec![(ordinary_scheduling, "bookings".to_string())];
    let ordinary: Value = yaml_value(RUNTIME).unwrap();
    for name in ["applications", "notices"] {
        let mut doc = ordinary.clone();
        // Even a matching ordinary credential would be ignored by these adapters.
        doc["connections"][name]["observationAuthorization"] =
            doc["connections"][name]["authorization"].clone();
        doc["connections"][name]["observationAuthorization"]["clientId"] = json!(CANARY);
        cases.push((doc, name.into()));
    }
    let mut task_breg = ordinary.clone();
    task_breg["connections"]["applications"]["authorization"]["taskAuthority"] =
        scheduling["connections"]["bookings"]["authorization"]["taskAuthority"].clone();
    task_breg["connections"]["applications"]["observationAuthorization"] =
        ordinary["connections"]["applications"]["authorization"].clone();
    cases.push((task_breg, "applications".into()));
    for (doc, name) in cases {
        let error = refused(&serde_norway::to_string(&doc).unwrap());
        assert_eq!(
            error.field.as_deref(),
            Some(format!("/connections/{name}/observationAuthorization").as_str())
        );
        assert!(
            error.code == "config.unknown-key"
                || error
                    .suggested_action
                    .as_deref()
                    .unwrap()
                    .contains("remove observationAuthorization")
        );
        assert!(!error.to_string().contains(CANARY));
    }
    load(SCHEDULING_RUNTIME).unwrap();
    load(RUNTIME).unwrap();
}

#[test]
fn binding_identity_never_resolves_secrets_and_pins_audience_and_task_authority() {
    let mut config = load(RUNTIME).unwrap();
    let document = config.document().unwrap();
    assert_eq!(document["apiVersion"], API_VERSION);
    assert_eq!(document["kind"], KIND);
    let restored = load(&serde_norway::to_string(&document).unwrap()).unwrap();
    assert_eq!(
        config.binding_digest().unwrap(),
        restored.binding_digest().unwrap()
    );
    let digest = config.binding_digest().unwrap();
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .signing_key_ref =
        registry_platform_config::SecretReference::parse("secret:file/another-unavailable-key")
            .unwrap();
    assert_eq!(digest, config.binding_digest().unwrap());
    let audience = config.connections["applications"]
        .authorization()
        .unwrap()
        .token_endpoint
        .as_str()
        .to_owned();
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .client_assertion_audience = Some(audience);
    assert_eq!(digest, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .client_assertion_audience = Some("http://127.0.0.1:8090".into());
    assert_ne!(digest, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .task_authority = Some(registry_coordinator::runtime::TaskAuthorityConfig {
        base_url: "http://127.0.0.1:8200".parse().unwrap(),
        issuer: "urn:example:casework".into(),
        subject: "synthetic-agent".into(),
        exchange_audience: "urn:example:exchange".into(),
        bootstrap_resource: "urn:example:casework".into(),
    });
    let task = config.binding_digest().unwrap();
    assert_ne!(digest, task);
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .task_authority
        .as_mut()
        .unwrap()
        .subject = "another-agent".into();
    assert_ne!(task, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .task_authority = config.connections["applications"]
        .authorization()
        .unwrap()
        .task_authority
        .clone();
    assert!(config.binding_digest().is_err());
}

#[test]
fn initialized_project_is_four_offline_checkable_files_and_a_gitignore_and_never_overwrites() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("flow");
    project::init(&path, None).unwrap();
    let mut names = fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            ".gitignore",
            "functions.rhai",
            "runtime.yaml",
            "scenarios.yaml",
            "workflow.yaml"
        ]
    );
    let config = RuntimeConfig::load(&path.canonicalize().unwrap().join("runtime.yaml")).unwrap();
    let definition = Definition::load(&path).unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    let explanation = definition.explain().unwrap();
    assert_eq!(explanation["workflowRevision"], definition.digest);
    assert!(explanation["operations"].is_object());
    assert!(explanation["functions"].is_object());
    assert_eq!(explanation["steps"].as_array().unwrap().len(), 6);
    assert_eq!(explanation["limits"]["operations"], 100000);
    fs::write(path.join("functions.rhai"), CANARY).unwrap();
    assert!(project::init(&path, None).is_err());
    assert_eq!(
        fs::read_to_string(path.join("functions.rhai")).unwrap(),
        CANARY
    );
}

#[cfg(feature = "schema")]
#[test]
fn generated_runtime_schema_matches_examples_and_shared_blocks() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let config: Value = yaml_value(RUNTIME).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(validator.is_valid(&config));
    let single_flow: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/single-flow-runtime.yaml"
    ))
    .unwrap();
    assert!(validator.is_valid(&single_flow));
    assert!(validator.is_valid(&yaml_value(REVIEW_RUNTIME).unwrap()));
    let mut scheduling: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    assert!(validator.is_valid(&scheduling));
    scheduling["connections"]["bookings"]
        .as_object_mut()
        .unwrap()
        .remove("observationAuthorization");
    assert!(!validator.is_valid(&scheduling));
    scheduling["connections"]["bookings"]["observationAuthorization"] = Value::Null;
    assert!(!validator.is_valid(&scheduling));
    scheduling["connections"]["bookings"]["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("taskAuthority");
    scheduling["connections"]["bookings"]
        .as_object_mut()
        .unwrap()
        .remove("observationAuthorization");
    assert!(validator.is_valid(&scheduling));
    let original_scheduling: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    scheduling["connections"]["bookings"]["observationAuthorization"] =
        original_scheduling["connections"]["bookings"]["observationAuthorization"].clone();
    assert!(
        !validator.is_valid(&scheduling),
        "ordinary Scheduling must not accept ignored observation authority"
    );
    for name in ["applications", "notices"] {
        let mut invalid = config.clone();
        invalid["connections"][name]["observationAuthorization"] =
            original_scheduling["connections"]["bookings"]["observationAuthorization"].clone();
        assert!(!validator.is_valid(&invalid));
    }
    let canonical: Value =
        serde_json::from_str(&registry_platform_config::schema::shared_blocks_document().unwrap())
            .unwrap();
    for block in [
        "SecretProvidersConfig",
        "FileSecretProviderConfig",
        "EnvironmentSecretProviderConfig",
    ] {
        assert_eq!(schema["$defs"][block], canonical["$defs"][block]);
    }
    let mut wrong = config;
    wrong["kind"] = json!("wrong");
    assert!(!validator.is_valid(&wrong));
}

#[test]
fn appointment_workflow_refuses_ordinary_authority_before_admission_or_activation() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        include_str!("../../../products/coordinator/examples/deferred-appointment/workflow.yaml"),
    )
    .unwrap();
    fs::write(
        root.path().join("functions.rhai"),
        include_str!("../../../products/coordinator/examples/deferred-appointment/functions.rhai"),
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let mut config = load(SCHEDULING_RUNTIME).unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    config
        .connections
        .get_mut("bookings")
        .unwrap()
        .authorization_mut()
        .unwrap()
        .task_authority = None;
    let registry_coordinator::runtime::ConnectionConfig::Scheduling(binding) =
        config.connections.get_mut("bookings").unwrap()
    else {
        panic!("scheduling connection")
    };
    binding.observation_authorization = None;
    config.validate().unwrap();
    let error = config.validate_workflow(&definition.workflow).unwrap_err();
    assert_eq!(error.code, "workflow-binding");
    assert_eq!(error.field.as_deref(), Some("steps.book.call"));
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("connections.bookings.authorization.taskAuthority"));
    assert!(config.binding_digest_for(&definition.workflow).is_err());
    let mut read_only: Value = document_value(
        include_str!("../../../products/coordinator/examples/deferred-appointment/workflow.yaml"),
        registry_coordinator::authoring::API_VERSION,
        registry_coordinator::authoring::KIND,
    )
    .unwrap();
    read_only["workflow"]["start"] = json!("metadata");
    read_only.as_object_mut().unwrap().remove("functions");
    read_only["operations"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| name == "catalogue-read-scheduling");
    read_only["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| matches!(name.as_str(), "metadata" | "skipped"));
    read_only["workflow"]["steps"]["metadata"]["next"] = json!("skipped");
    read_only["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| name == "no-current-eligibility");
    fs::write(
        root.path().join("workflow.yaml"),
        serde_norway::to_string(&read_only).unwrap(),
    )
    .unwrap();
    let read_only = Definition::load(root.path()).unwrap();
    config.validate_workflow(&read_only.workflow).unwrap();
}

#[test]
fn proposal_lifecycle_refuses_task_grant_only_bindings_before_admission() {
    use registry_coordinator::{definition::Step, protocol::Operation};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/proposal-follow-up");
    let definition = Definition::load(&root).unwrap();
    let mut config = load(include_str!(
        "../../../products/coordinator/examples/proposal-follow-up/runtime.yaml"
    ))
    .unwrap();
    let task_config = load(SCHEDULING_RUNTIME).unwrap();
    let authority = task_config.connections["bookings"]
        .authorization()
        .unwrap()
        .task_authority
        .clone();
    for operation in [
        Operation::InvokeBregAction,
        Operation::SubmitBregProposal,
        Operation::ApplyBregProposal,
        Operation::RetryBregProposal,
        Operation::CancelBregProposal,
    ] {
        let mut workflow = definition.workflow.clone();
        for step in workflow.steps.values_mut() {
            if let Step::Call { call, .. } = step {
                if call.connection == "facilities" {
                    call.operation = operation;
                }
            }
        }
        config
            .connections
            .get_mut("facilities")
            .unwrap()
            .authorization_mut()
            .unwrap()
            .task_authority = None;
        config.validate_workflow(&workflow).unwrap();
        config
            .connections
            .get_mut("facilities")
            .unwrap()
            .authorization_mut()
            .unwrap()
            .task_authority = authority.clone();
        let error = config.validate_workflow(&workflow).unwrap_err();
        assert_eq!(error.code, "workflow-binding");
        assert_eq!(
            error.field.as_deref(),
            Some("/workflow/steps/start-draft/operation")
        );
        assert!(config.binding_digest_for(&workflow).is_err());
    }
}

#[test]
fn caller_policy_flow_ids_use_the_workflow_name_grammar() {
    let original: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/single-flow-runtime.yaml"
    ))
    .unwrap();
    for invalid in [
        format!("flow.{CANARY}"),
        format!("flow\n{CANARY}"),
        format!("flow\0{CANARY}"),
        "日本語".into(),
        "a".repeat(65),
    ] {
        let mut document = original.clone();
        let invalid_type = invalid.chars().any(char::is_control);
        document["deployment"]["authentication"]["policies"]["institution-producer"]["workflows"] =
            json!([invalid]);
        let error = refused(&serde_norway::to_string(&document).unwrap());
        if invalid_type {
            assert!(matches!(
                error.code.as_str(),
                "config.invalid-value" | "yaml.control-character"
            ));
        } else {
            assert_eq!(error.code, "coordinator.access.configuration");
        }
        assert!(!error.to_string().contains(CANARY));
    }
    // Policy entries may name other or retained workflows, not just the active
    // package. Offline syntax checks do not load a package or contact its issuer.
    let mut document = original;
    document["deployment"]["authentication"]["policies"]["institution-producer"]["workflows"] =
        json!(["a".repeat(64), "Retained_flow-1"]);
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
}

const DEPLOYMENT_ACTIONS: [&str; 6] = [
    "doctor",
    "restore-hold",
    "release-restore-hold",
    "release-admission-hold",
    "complete-execution-recovery",
    "retain",
];

/// `flows` scopes run actions only. A policy listing only deployment-wide
/// actions is an operator of the whole deployment and lists no flow.
#[test]
fn flows_scope_run_actions_and_deployment_operators_list_none() {
    let original: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/single-flow-runtime.yaml"
    ))
    .unwrap();
    #[cfg(feature = "schema")]
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    #[cfg(feature = "schema")]
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let with_operator = |policy: Value| {
        let mut document = original.clone();
        document["deployment"]["authentication"]["policies"]["institution-operator"] = policy;
        document
    };

    let deployment_operator = with_operator(json!({
                "requiredScopes": ["coordinator:operate"],
        "actions": DEPLOYMENT_ACTIONS,
        "operator": true,
    }));
    load(&serde_norway::to_string(&deployment_operator).unwrap()).unwrap();
    #[cfg(feature = "schema")]
    assert!(validator.is_valid(&deployment_operator));

    // A flow list on a policy without run actions would read as a limit it is
    // not, so it is refused rather than ignored.
    let mut listed = deployment_operator.clone();
    listed["deployment"]["authentication"]["policies"]["institution-operator"]["workflows"] =
        json!(["delayed-follow-up"]);
    let error = refused(&serde_norway::to_string(&listed).unwrap());
    assert_eq!(error.code, "coordinator.access.configuration");
    assert_eq!(
        error.field.as_deref(),
        Some("/deployment/authentication/policies/institution-operator/workflows")
    );
    let advice = error.suggested_action.as_deref().unwrap();
    assert!(advice.contains("remove workflows"), "{advice}");

    // Every run action needs the flows it may reach, for producers and
    // operators alike.
    for (index, actions, operator) in [
        ("institution-producer", json!(["start", "status"]), false),
        ("institution-operator", json!(["inspect"]), true),
        ("institution-operator", json!(["doctor", "reconcile"]), true),
    ] {
        let mut document = original.clone();
        let policy = &mut document["deployment"]["authentication"]["policies"][index];
        policy.as_object_mut().unwrap().remove("workflows");
        policy["actions"] = actions.clone();
        policy["operator"] = json!(operator);
        let error = refused(&serde_norway::to_string(&document).unwrap());
        assert_eq!(error.code, "coordinator.access.configuration", "{actions}");
        assert_eq!(
            error.field.as_deref(),
            Some(format!("/deployment/authentication/policies/{index}/workflows").as_str()),
            "{actions}"
        );
        let advice = error.suggested_action.as_deref().unwrap();
        assert!(advice.contains("run actions"), "{advice}");
    }

    // Deployment-wide actions stay an operator's, with or without flows.
    let mut not_operator = deployment_operator.clone();
    not_operator["deployment"]["authentication"]["policies"]["institution-operator"]["operator"] =
        json!(false);
    let error = refused(&serde_norway::to_string(&not_operator).unwrap());
    assert_eq!(error.code, "coordinator.access.configuration");
    assert_eq!(
        error.field.as_deref(),
        Some("/deployment/authentication/policies/institution-operator/actions")
    );
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("operator: true"));

    // An operator that also takes run actions keeps its flow list for them.
    load(&serde_norway::to_string(&original).unwrap()).unwrap();
}

#[test]
fn the_metrics_listener_is_optional_private_and_apart_from_the_listener() {
    let original: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/single-flow-runtime.yaml"
    ))
    .unwrap();
    assert!(load(&serde_norway::to_string(&original).unwrap())
        .unwrap()
        .deployment
        .expect("deployment")
        .metrics_listener
        .is_none());
    #[cfg(feature = "schema")]
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    #[cfg(feature = "schema")]
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let with_metrics = |metrics: Value| {
        let mut document = original.clone();
        document["deployment"]["metricsListener"] = metrics;
        document
    };
    for bind in [
        "127.0.0.1:8108",
        "0.0.0.0:9090",
        "[::]:9090",
        "203.0.113.4:9090",
        "127.0.0.1:0",
        "[2001:db8::1]:9090",
    ] {
        let error =
            refused(&serde_norway::to_string(&with_metrics(json!({"bind": bind}))).unwrap());
        assert_eq!(error.code, "coordinator.deployment.configuration", "{bind}");
        assert_eq!(
            error.field.as_deref(),
            Some("/deployment/metricsListener/bind"),
            "{bind}"
        );
        assert!(error
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("loopback or private address"));
        assert!(!format!("{error}").contains(bind), "{bind}");
        assert!(!format!("{error:?}").contains(bind), "{bind}");
    }
    let private = with_metrics(json!({"bind": "127.0.0.1:9108"}));
    let deployment = load(&serde_norway::to_string(&private).unwrap())
        .unwrap()
        .deployment
        .expect("deployment");
    assert_eq!(
        deployment
            .metrics_listener
            .expect("metrics listener")
            .bind
            .socket_addr(),
        "127.0.0.1:9108".parse().unwrap()
    );
    #[cfg(feature = "schema")]
    {
        assert!(validator.is_valid(&private));
        assert!(!validator.is_valid(&with_metrics(
            json!({"bind": "127.0.0.1:9108", "tlsTermination": "operator-controlled-upstream"})
        )));
        assert!(!validator.is_valid(&with_metrics(json!({}))));
    }
}

#[test]
fn database_reference_requires_an_enabled_provider_without_resolving_values() {
    const REFERENCE_CANARY: &str = "UNDECLARED_DATABASE_REFERENCE_CANARY";
    let mut document: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/single-flow-runtime.yaml"
    ))
    .unwrap();
    // Keep every migration/deployment reference on the enabled file provider.
    // Only the runtime URL uses the disabled environment provider.
    document["database"]["migrationUrlRef"] = json!("secret:file/migration-url");
    document["secretProviders"]
        .as_object_mut()
        .unwrap()
        .remove("environment");
    document["database"]["runtimeUrlRef"] = json!(format!("secret:env/{REFERENCE_CANARY}"));
    let error = refused(&serde_norway::to_string(&document).unwrap());
    assert_eq!(error.code, "coordinator.runtime-config.refused");
    assert_eq!(error.field.as_deref(), Some("/database/runtimeUrlRef"));
    assert!(!error.to_string().contains(REFERENCE_CANARY));
    assert!(error.suggested_action.is_some());
    // Enabling the provider is sufficient for offline validation even though
    // the referenced value has not been provisioned. Apply retains its separate
    // migration reference and must not read runtime credentials here.
    document["secretProviders"]["environment"] = json!({});
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
    document["secretProviders"]
        .as_object_mut()
        .unwrap()
        .remove("environment");
    document["database"]["runtimeUrlRef"] = json!("secret:file/unprovisioned-runtime-url");
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
}

#[test]
fn primary_signing_references_require_the_enabled_file_provider_offline() {
    let task_runtime: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    for (runtime, connection, task_bound) in [
        (RUNTIME, "applications", false),
        (RUNTIME, "applications", true),
        (RUNTIME, "notices", false),
        (SCHEDULING_RUNTIME, "bookings", false),
    ] {
        let mut document: Value = yaml_value(runtime).unwrap();
        let mut binding = document["connections"][connection].clone();
        if task_bound {
            binding["authorization"]["taskAuthority"] =
                task_runtime["connections"]["bookings"]["authorization"]["taskAuthority"].clone();
        } else {
            binding["authorization"]
                .as_object_mut()
                .unwrap()
                .remove("taskAuthority");
        }
        binding
            .as_object_mut()
            .unwrap()
            .remove("observationAuthorization");
        binding["authorization"]["signingKeyRef"] = json!(format!("secret:file/{CANARY}"));
        document["connections"] = json!({connection:binding});
        document.as_object_mut().unwrap().remove("deployment");
        document["secretProviders"] = json!({"environment":{}});
        document["database"]
            .as_object_mut()
            .unwrap()
            .remove("trustedRootCertificateRef");
        let error = refused(&serde_norway::to_string(&document).unwrap());
        assert_eq!(error.code, "coordinator.runtime-config.refused");
        assert_eq!(
            error.field.as_deref(),
            Some(format!("/connections/{connection}/authorization/signingKeyRef").as_str())
        );
        assert!(!error.to_string().contains(CANARY));
        assert!(error
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("secretProviders.file"));
        // No file exists: enabling its provider still permits offline checking,
        // including the primary identity used for task bootstrap and exchange.
        let keys = tempfile::tempdir().unwrap();
        assert!(!keys.path().join(CANARY).exists());
        document["secretProviders"]["file"] = json!({"root":keys.path()});
        load(&serde_norway::to_string(&document).unwrap()).unwrap();
    }
}

#[test]
fn observation_signing_reference_requires_the_enabled_file_provider_offline() {
    let mut document: Value = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let mut binding = document["connections"]["bookings"].clone();
    binding["observationAuthorization"]["signingKeyRef"] = json!(format!("secret:file/{CANARY}"));
    document["connections"] = json!({"bookings":binding});
    document.as_object_mut().unwrap().remove("deployment");
    document["secretProviders"] = json!({"environment":{}});
    document["database"]
        .as_object_mut()
        .unwrap()
        .remove("trustedRootCertificateRef");
    let error = refused(&serde_norway::to_string(&document).unwrap());
    assert_eq!(error.code, "coordinator.runtime-config.refused");
    assert_eq!(
        error.field.as_deref(),
        Some("/connections/bookings/observationAuthorization/signingKeyRef")
    );
    assert!(!error.to_string().contains(CANARY));
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("secretProviders.file"));
    // The observation key may differ from the primary key. Offline validation
    // checks both references structurally and must not try to read either key.
    let keys = tempfile::tempdir().unwrap();
    assert!(!keys.path().join(CANARY).exists());
    document["secretProviders"]["file"] = json!({"root":keys.path()});
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
}

#[test]
fn shared_runtime_check_retains_all_independent_positions_without_secret_io() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    let mut document = yaml_value(RUNTIME).unwrap();
    document["namespace"] = json!("invalid");
    document["connections"]["applications"]["baseUrl"] = json!("http://public.invalid");
    document["connections"]["notices"]["authorization"]["resource"] = json!("invalid resource");
    fs::write(&path, serde_norway::to_string(&document).unwrap()).unwrap();
    let checked = RuntimeConfig::check_file(&path, false);
    let errors = checked
        .diagnostics
        .iter()
        .filter(|d| d.severity == registry_platform_yaml::Severity::Error)
        .collect::<Vec<_>>();
    for pointer in [
        "/namespace",
        "/connections/applications/baseUrl",
        "/connections/notices/authorization/resource",
    ] {
        let diagnostic = errors
            .iter()
            .find(|d| d.path == pointer)
            .expect("independent positioned error");
        assert!(diagnostic.source.as_ref().unwrap().line.is_some());
        assert!(diagnostic.source.as_ref().unwrap().column.is_some());
        assert!(!diagnostic.suggested_action.is_empty());
    }
    assert!(root.path().read_dir().unwrap().all(|entry| entry
        .unwrap()
        .path()
        .canonicalize()
        .unwrap()
        == path));
}

#[test]
fn shared_runtime_check_defers_environment_without_reading_secret_references() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    let text = RUNTIME.replace(
        "http://127.0.0.1:8100",
        "${COORDINATOR_CONFIG_OFFLINE_ENDPOINT}",
    );
    fs::write(&path, text).unwrap();
    let checked = RuntimeConfig::check_file(&path, false);
    assert!(checked.loaded.is_some());
    assert!(checked.defers("/connections/applications/baseUrl"));
    assert!(checked
        .diagnostics
        .iter()
        .all(|d| d.severity != registry_platform_yaml::Severity::Error));
}

#[test]
fn shared_runtime_reports_all_unknown_members_and_refuses_null_and_duplicate_sets() {
    let mut document = yaml_value(RUNTIME).unwrap();
    document["unknownOne"] = json!(true);
    document["connections"]["applications"]["unknownTwo"] = json!(false);
    let error = refused(&serde_norway::to_string(&document).unwrap());
    for pointer in ["/unknownOne", "/connections/applications/unknownTwo"] {
        assert!(error.diagnostics.iter().any(|d| d.path == pointer));
    }
    let mut document = yaml_value(RUNTIME).unwrap();
    document["connections"]["applications"]["profile"] = Value::Null;
    assert_eq!(
        refused(&document.to_string()).field.as_deref(),
        Some("/connections/applications/profile")
    );
    let mut document = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let policies = &mut document["deployment"]["authentication"]["policies"];
    policies["institution-producer"]["actions"] = json!(["start", "start"]);
    let error = refused(&document.to_string());
    assert_eq!(error.code, "config.duplicate-item");
    assert!(error
        .field
        .as_deref()
        .unwrap()
        .starts_with("/deployment/authentication/policies/institution-producer/actions"));
}

const SINGLE_FLOW: &str =
    include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn deployment_packages_list_one_pinned_package_per_flow() {
    let original: Value = yaml_value(SINGLE_FLOW).unwrap();
    #[cfg(feature = "schema")]
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    #[cfg(feature = "schema")]
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let pin = |root: &str, digest: &str| json!({"root": root, "expectedDigest": digest});
    let other = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    // JSON Schema compares whole items, so distinct pins sharing one root
    // pass the schema and are refused at load.
    for (packages, pointer, advice, schema_refuses) in [
        (
            json!([]),
            "/deployment/packages",
            "one pinned package per workflow",
            true,
        ),
        (
            Value::Array(
                (0..17)
                    .map(|i| pin(&format!("/opt/registry-coordinator/flow-{i}"), ZERO_DIGEST))
                    .collect(),
            ),
            "/deployment/packages",
            "at most sixteen",
            true,
        ),
        (
            json!([pin("/opt/a", ZERO_DIGEST), pin("/opt/a", other)]),
            "/deployment/packages/1/root",
            "once",
            false,
        ),
        (
            json!([pin("/opt/a", ZERO_DIGEST), {"root": "/opt/b"}]),
            "/deployment/packages/1/expectedDigest",
            "pin the immutable package digest",
            true,
        ),
        (
            json!([pin("/opt/a", ZERO_DIGEST), pin("relative/b", other)]),
            "/deployment/packages/1/root",
            "absolute package root",
            true,
        ),
    ] {
        let mut document = original.clone();
        document["deployment"]["packages"] = packages;
        let error = refused(&serde_norway::to_string(&document).unwrap());
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|d| d.path == pointer)
            .unwrap_or_else(|| panic!("{pointer} names the refused pin: {error:?}"));
        assert!(
            diagnostic.suggested_action.contains(advice),
            "{pointer}: {}",
            diagnostic.suggested_action
        );
        #[cfg(feature = "schema")]
        assert_eq!(!validator.is_valid(&document), schema_refuses, "{pointer}");
        #[cfg(not(feature = "schema"))]
        let _ = schema_refuses;
    }
    let mut document = original.clone();
    document["deployment"]["packages"] =
        json!([pin("/opt/a", ZERO_DIGEST), pin("/opt/a", ZERO_DIGEST)]);
    let error = refused(&serde_norway::to_string(&document).unwrap());
    assert!(error
        .diagnostics
        .iter()
        .any(|d| d.path == "/deployment/packages/1/root"));
    #[cfg(feature = "schema")]
    assert!(!validator.is_valid(&document));
    let mut document = original.clone();
    let deployment = document["deployment"].as_object_mut().unwrap();
    let packages = deployment.remove("packages").unwrap();
    deployment.insert("package".into(), packages[0].clone());
    let error = refused(&serde_norway::to_string(&document).unwrap());
    assert!(error
        .diagnostics
        .iter()
        .any(|d| d.path == "/deployment/package"));
    #[cfg(feature = "schema")]
    assert!(!validator.is_valid(&document));
    let mut document = original;
    document["deployment"]["packages"] = json!([
        pin("/opt/registry-coordinator/a", ZERO_DIGEST),
        pin("/opt/registry-coordinator/b", other)
    ]);
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
    #[cfg(feature = "schema")]
    assert!(validator.is_valid(&document));
}

#[test]
fn two_flow_example_serves_two_example_projects() {
    let text = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/coordinator/examples/two-flow-runtime.yaml"
    ))
    .unwrap();
    let config = load(&text).unwrap();
    let packages = &config.deployment.as_ref().unwrap().packages;
    assert_eq!(packages.len(), 2);
    #[cfg(feature = "schema")]
    {
        let schema: Value =
            serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap())
                .unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        assert!(validator.is_valid(&yaml_value(&text).unwrap()));
    }
    let mut flows = Vec::new();
    for project in ["delayed-follow-up", "governed-action-follow-up"] {
        let definition = Definition::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/coordinator/examples")
                .join(project),
        )
        .unwrap();
        config.validate_workflow(&definition.workflow).unwrap();
        flows.push(definition.workflow.id.clone());
    }
    let policies = yaml_value(&text).unwrap()["deployment"]["authentication"]["policies"].clone();
    for flow in &flows {
        assert!(
            policies
                .as_object()
                .unwrap()
                .values()
                .any(|policy| policy["workflows"] == json!([flow])),
            "{flow} has a producer limited to that flow"
        );
    }
    assert!(
        policies.as_object().unwrap().values().any(|policy| {
            policy["operator"] == json!(true)
                && policy.get("workflows").is_none()
                && policy["actions"] == json!(DEPLOYMENT_ACTIONS)
        }),
        "a deployment operator takes every deployment-wide action without a flow list"
    );
}

fn with_review_connection() -> Value {
    let mut document: Value = yaml_value(RUNTIME).unwrap();
    document["connections"]["review"] = json!({
        "type": "casework-review-producer",
        "baseUrl": "http://127.0.0.1:8102",
        "profile": "coordinator-producer",
        "producer": "coordinator",
        "authorization": {
            "tokenEndpoint": "http://127.0.0.1:8090/token",
            "clientId": "coordinator-producer",
            "signingKeyRef": "secret:file/client-key",
            "resource": "urn:example:casework",
            "scopes": ["casework:review"]
        },
        "completion": {
            "recipientBinding": "coordinator-v1",
            "bearerTokenRef": "secret:file/review-completion-token"
        },
        "resultCheckSeconds": 900
    });
    document
}

fn finding_at(error: &registry_coordinator::CoordinatorError, pointer: &str) -> String {
    let found = error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.path == pointer)
        .unwrap_or_else(|| {
            panic!(
                "expected a finding at {pointer}, got {:?}",
                error
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.path.clone())
                    .collect::<Vec<_>>()
            )
        });
    format!(
        "{} {} {}",
        found.code, found.message, found.suggested_action
    )
}

#[test]
fn reviewed_notice_runtime_receives_completions_for_its_review_connection_on_the_main_listener() {
    let config = load(REVIEW_RUNTIME).unwrap();
    let definition = Definition::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/examples/reviewed-notice"),
    )
    .unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    let review = config.connections["review"].product_binding().unwrap();
    assert!(matches!(
        review.product,
        registry_coordinator::runtime::Product::Casework
    ));
    assert_eq!(
        review.profile.map(String::as_str),
        Some("coordinator-producer")
    );
    assert_eq!(review.producer.map(String::as_str), Some("coordinator"));
    assert_eq!(config.connections["review"].result_check_seconds(), 900);
    let completion = review.completion.as_ref().unwrap();
    assert_eq!(completion.recipient_binding, "coordinator-v1");
    assert_eq!(
        completion.bearer_token_ref.as_str(),
        "secret:file/review-completion-token"
    );
    assert!(config.connections["notices"]
        .product_binding()
        .unwrap()
        .completion
        .is_none());
    let document = yaml_value(REVIEW_RUNTIME).unwrap();
    assert!(document["deployment"]["listener"]["bind"].is_string());
    let policies = document["deployment"]["authentication"]["policies"]
        .as_object()
        .unwrap();
    assert!(policies
        .values()
        .all(|policy| policy["workflows"] == json!(["reviewed-notice"])));
    assert!(policies.values().any(|policy| policy["operator"] == true));
}

#[test]
fn casework_connections_name_a_producer_profile_and_bounded_result_checks_offline() {
    let original = with_review_connection();
    let config = load(&original.to_string()).unwrap();
    let review = config.connections["review"].product_binding().unwrap();
    assert!(matches!(
        review.product,
        registry_coordinator::runtime::Product::Casework
    ));
    assert_eq!(review.producer.map(String::as_str), Some("coordinator"));
    assert_eq!(config.connections["review"].result_check_seconds(), 900);
    let mut defaulted = original.clone();
    defaulted["connections"]["review"]
        .as_object_mut()
        .unwrap()
        .remove("resultCheckSeconds");
    assert_eq!(
        load(&defaulted.to_string()).unwrap().connections["review"].result_check_seconds(),
        900
    );
    let mut polling_only = original.clone();
    polling_only["connections"]["review"]
        .as_object_mut()
        .unwrap()
        .remove("completion");
    load(&polling_only.to_string()).unwrap();

    for member in ["producer", "profile"] {
        let mut document = original.clone();
        document["connections"]["review"]
            .as_object_mut()
            .unwrap()
            .remove(member);
        let error = refused(&document.to_string());
        finding_at(&error, "/connections/review");
        assert!(error
            .suggested_action
            .as_deref()
            .unwrap_or("")
            .contains(member));
    }
    for (member, value) in [
        ("producer", json!(format!("Not {CANARY}"))),
        ("profile", json!(format!("{CANARY}/control"))),
    ] {
        let mut document = original.clone();
        document["connections"]["review"][member] = value;
        let error = refused(&document.to_string());
        finding_at(&error, &format!("/connections/review/{member}"));
        assert!(!error.to_string().contains(CANARY));
        assert!(!format!("{:?}", error.diagnostics).contains(CANARY));
    }
    for seconds in [59, 86_401] {
        let mut document = original.clone();
        document["connections"]["review"]["resultCheckSeconds"] = json!(seconds);
        let error = refused(&document.to_string());
        assert!(finding_at(&error, "/connections/review/resultCheckSeconds")
            .starts_with("config.out-of-range"));
    }
    for binding in [
        json!(""),
        json!(format!("{CANARY} with space")),
        json!("x".repeat(257)),
    ] {
        let mut document = original.clone();
        document["connections"]["review"]["completion"]["recipientBinding"] = binding;
        let error = refused(&document.to_string());
        finding_at(&error, "/connections/review/completion/recipientBinding");
        assert!(!format!("{:?}", error.diagnostics).contains(CANARY));
    }
    let mut unknown = original.clone();
    unknown["connections"]["review"]["completion"]["header"] = json!("x-completion");
    refused(&unknown.to_string());

    let mut disabled = original.clone();
    disabled["secretProviders"]
        .as_object_mut()
        .unwrap()
        .remove("file");
    let error = refused(&disabled.to_string());
    assert!(
        finding_at(&error, "/connections/review/completion/bearerTokenRef")
            .contains("secretProviders")
    );

    let mut task = original.clone();
    task["connections"]["review"]["authorization"]["taskAuthority"] =
        yaml_value(SCHEDULING_RUNTIME).unwrap()["connections"]["bookings"]["authorization"]
            ["taskAuthority"]
            .clone();
    let error = refused(&task.to_string());
    finding_at(&error, "/connections/review/authorization/taskAuthority");

    for (connection, member, value) in [
        ("notices", "producer", json!("coordinator")),
        ("applications", "producer", json!("coordinator")),
        (
            "notices",
            "completion",
            original["connections"]["review"]["completion"].clone(),
        ),
        ("applications", "resultCheckSeconds", json!(900)),
    ] {
        let mut document = original.clone();
        document["connections"][connection][member] = value;
        let error = refused(&document.to_string());
        assert!(
            finding_at(&error, &format!("/connections/{connection}/{member}"))
                .starts_with("config.unknown-key")
        );
    }

    let mut twice = original.clone();
    twice["connections"]["second-review"] = original["connections"]["review"].clone();
    twice["connections"]["second-review"]["producer"] = json!("second-producer");
    let error = refused(&twice.to_string());
    finding_at(
        &error,
        "/connections/second-review/completion/recipientBinding",
    );
    twice["connections"]["second-review"]["completion"]["recipientBinding"] =
        json!("coordinator-v2");
    load(&twice.to_string()).unwrap();
}

#[test]
fn casework_binding_identity_pins_the_producer_but_not_delivery_settings() {
    let plain = load(RUNTIME).unwrap();
    let mut without_review = with_review_connection();
    without_review["connections"]
        .as_object_mut()
        .unwrap()
        .remove("review");
    assert_eq!(
        plain.binding_digest().unwrap(),
        load(&without_review.to_string())
            .unwrap()
            .binding_digest()
            .unwrap(),
        "adding Casework support leaves existing binding identities unchanged"
    );
    let original = with_review_connection();
    let digest = load(&original.to_string())
        .unwrap()
        .binding_digest()
        .unwrap();
    let mut producer = original.clone();
    producer["connections"]["review"]["producer"] = json!("another-producer");
    assert_ne!(
        digest,
        load(&producer.to_string())
            .unwrap()
            .binding_digest()
            .unwrap(),
        "the producer is part of every submission digest"
    );
    // How a waiting run is woken is not command identity: an operator can
    // rotate the token, rename the recipient or tune result checks without
    // stranding runs admitted under the earlier settings.
    let mut delivery = original.clone();
    delivery["connections"]["review"]["completion"]["bearerTokenRef"] =
        json!("secret:file/another-completion-token");
    delivery["connections"]["review"]["completion"]["recipientBinding"] = json!("coordinator-v2");
    delivery["connections"]["review"]["resultCheckSeconds"] = json!(60);
    assert_eq!(
        digest,
        load(&delivery.to_string())
            .unwrap()
            .binding_digest()
            .unwrap()
    );
}

#[cfg(feature = "schema")]
#[test]
fn generated_runtime_schema_describes_casework_connections() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let original = with_review_connection();
    assert!(validator.is_valid(&original));
    let connection = &schema["$defs"]["ConnectionConfig"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["type"]["const"] == "casework-review-producer")
        .unwrap()["properties"];
    assert_eq!(connection["resultCheckSeconds"]["default"], json!(900));
    assert_eq!(connection["resultCheckSeconds"]["minimum"], json!(60));
    assert_eq!(connection["resultCheckSeconds"]["maximum"], json!(86_400));
    for member in ["producer", "profile"] {
        let mut missing = original.clone();
        missing["connections"]["review"]
            .as_object_mut()
            .unwrap()
            .remove(member);
        assert!(!validator.is_valid(&missing), "{member}");
    }
    for (connection, member, value) in [
        ("notices", "producer", json!("coordinator")),
        (
            "applications",
            "completion",
            original["connections"]["review"]["completion"].clone(),
        ),
        ("notices", "resultCheckSeconds", json!(900)),
    ] {
        let mut document = original.clone();
        document["connections"][connection][member] = value;
        assert!(!validator.is_valid(&document), "{connection}.{member}");
    }
    let mut spaced = original;
    spaced["connections"]["review"]["completion"]["recipientBinding"] = json!("two words");
    assert!(!validator.is_valid(&spaced));
}

#[test]
fn tagged_connections_share_one_namespace_and_preserve_variant_checks() {
    let mut document = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let external = yaml_value(include_str!(
        "../../../products/coordinator/examples/external-directory/runtime.yaml"
    ))
    .unwrap();
    let evaluation = yaml_value(include_str!(
        "../../../products/coordinator/examples/decision-follow-up/runtime.yaml"
    ))
    .unwrap();
    document["connections"]["directory"] = external["connections"]["directory"].clone();
    document["connections"]["assessor"] = evaluation["connections"]["assessor"].clone();
    document["connections"]["review"] = with_review_connection()["connections"]["review"].clone();
    let config = load(&document.to_string()).unwrap();
    assert!(config.connections["directory"].external_http().is_some());
    assert!(config.connections["assessor"].decision().is_some());
    assert!(config.connections["review"].product_binding().is_some());
    let restored = load(&config.document().unwrap().to_string()).unwrap();
    assert_eq!(
        config.binding_digest().unwrap(),
        restored.binding_digest().unwrap()
    );
    #[cfg(feature = "schema")]
    {
        let schema: Value =
            serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap())
                .unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        assert!(validator.is_valid(&document));
    }
    for (connection, member, value) in [
        ("directory", "maximumResponseBytes", json!(65537)),
        ("assessor", "attemptTimeoutMilliseconds", json!(8001)),
        ("notices", "producer", json!("coordinator")),
        ("directory", "type", json!("messaging")),
    ] {
        let mut invalid = document.clone();
        invalid["connections"][connection][member] = value;
        let error = refused(&invalid.to_string());
        assert!(error
            .diagnostics
            .iter()
            .any(|d| d.path.starts_with(&format!("/connections/{connection}"))));
        assert!(error.diagnostics.iter().all(|d| d
            .source
            .as_ref()
            .is_some_and(|source| source.line.is_some() && source.column.is_some())));
    }
    for legacy in ["externalHttpConnections", "decisionConnections"] {
        let mut invalid = document.clone();
        invalid[legacy] = json!({});
        let error = refused(&invalid.to_string());
        assert_eq!(error.field.as_deref(), Some(format!("/{legacy}").as_str()));
    }
    let mut too_many = document;
    let binding = too_many["connections"]["directory"].clone();
    let connections = too_many["connections"].as_object_mut().unwrap();
    for index in 0..17 {
        connections.insert(format!("directory-{index}"), binding.clone());
    }
    assert_eq!(
        refused(&too_many.to_string()).field.as_deref(),
        Some("/connections")
    );
}

#[test]
fn external_and_evaluation_identity_permits_rotation_but_pins_authority_and_destination() {
    for (runtime, name, credential, authority) in [
        (
            include_str!("../../../products/coordinator/examples/decision-follow-up/runtime.yaml"),
            "assessor",
            vec!["authorization", "bearer", "tokenRef"],
            vec!["authorization", "bearer", "principal"],
        ),
        (
            include_str!("../../../products/coordinator/examples/external-directory/runtime.yaml"),
            "directory",
            vec!["authorization", "signingKeyRef"],
            vec!["authorization", "clientId"],
        ),
    ] {
        let mut document = yaml_value(runtime).unwrap();
        if name == "directory" {
            document["secretProviders"]["file"] =
                json!({"root":"/run/registry-coordinator/secrets"});
            document["connections"][name]["authorization"] = yaml_value(RUNTIME).unwrap()
                ["connections"]["applications"]["authorization"]
                .clone();
        }
        let original = load(&document.to_string())
            .unwrap()
            .binding_digest()
            .unwrap();
        let mut rotate = document.clone();
        let mut slot = &mut rotate["connections"][name];
        for part in &credential {
            slot = &mut slot[*part];
        }
        *slot = json!("secret:file/rotated-credential");
        assert_eq!(
            original,
            load(&rotate.to_string()).unwrap().binding_digest().unwrap()
        );
        let mut change = document.clone();
        let mut slot = &mut change["connections"][name];
        for part in &authority {
            slot = &mut slot[*part];
        }
        *slot = json!("different-principal");
        assert_ne!(
            original,
            load(&change.to_string()).unwrap().binding_digest().unwrap()
        );
        let mut redirect = document;
        redirect["connections"][name]["baseUrl"] = json!("https://different-service.example");
        assert_ne!(
            original,
            load(&redirect.to_string())
                .unwrap()
                .binding_digest()
                .unwrap()
        );
    }
}

#[test]
fn stricter_observation_spacing_is_bounded_and_part_of_the_binding() {
    let original = yaml_value(SCHEDULING_RUNTIME).unwrap();
    let default = load(&original.to_string()).unwrap();
    assert_eq!(default.minimum_observation_interval_seconds.get(), 30);
    let digest = default.binding_digest().unwrap();
    let mut strict = original.clone();
    strict["minimumObservationIntervalSeconds"] = json!(900);
    let strict = load(&strict.to_string()).unwrap();
    assert_eq!(strict.minimum_observation_interval_seconds.get(), 900);
    assert_ne!(digest, strict.binding_digest().unwrap());
    for seconds in [29, 86_401] {
        let mut invalid = original.clone();
        invalid["minimumObservationIntervalSeconds"] = json!(seconds);
        let error = refused(&invalid.to_string());
        assert_eq!(
            error.field.as_deref(),
            Some("/minimumObservationIntervalSeconds")
        );
        assert_eq!(error.code, "config.out-of-range");
    }
}

#[cfg(feature = "schema")]
#[test]
fn generated_runtime_schema_keeps_event_source_identifier_bounds() {
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    let mut fragment = json!({"$defs":schema["$defs"],"$ref":"#/$defs/EventSourcesUnderTest"});
    fragment["$defs"]["EventSourcesUnderTest"] = schema["properties"]["eventSources"].clone();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&fragment)
        .unwrap();
    let source = json!({"source":"urn:test:producer", "signingKeyRef":"secret:file/event-key"});
    assert!(validator.is_valid(&json!({"registry":source})));
    for key in ["Invalid", "../registry", "", "123"] {
        let invalid = json!({(key):source});
        assert!(!validator.is_valid(&invalid), "invalid source key {key:?}");
    }
    let too_many = (0..17)
        .map(|i| (format!("source-{i}"), source.clone()))
        .collect::<serde_json::Map<_, _>>();
    assert!(!validator.is_valid(&Value::Object(too_many)));
}
