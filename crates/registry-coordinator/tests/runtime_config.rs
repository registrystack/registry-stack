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
fn refused(text: &str) -> registry_coordinator::PocError {
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
fn admitted_clients_must_be_explicit_and_restricted() {
    let original = yaml_value(SCHEDULING_RUNTIME).unwrap();
    #[cfg(feature = "schema")]
    let schema: Value =
        serde_json::from_str(&registry_coordinator::runtime::runtime_schema().unwrap()).unwrap();
    #[cfg(feature = "schema")]
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    for (clients, code, pointer) in [
        (None, "config.missing-key", "/deployment/authentication"),
        (
            Some(json!([])),
            "config.invalid-value",
            "/deployment/authentication/allowedClients",
        ),
        (
            Some(json!("unrestricted")),
            "coordinator.access.configuration",
            "/deployment/authentication/allowedClients",
        ),
    ] {
        let mut document = original.clone();
        let authentication = document["deployment"]["authentication"]
            .as_object_mut()
            .unwrap();
        match clients {
            Some(value) => {
                authentication.insert("allowedClients".into(), value);
            }
            None => {
                authentication.remove("allowedClients");
            }
        }
        let error = refused(&document.to_string());
        assert_eq!(error.code, code);
        assert_eq!(error.field.as_deref(), Some(pointer));
        #[cfg(feature = "schema")]
        assert!(!validator.is_valid(&document));
    }
    load(&original.to_string()).unwrap();
    #[cfg(feature = "schema")]
    assert!(validator.is_valid(&original));
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
    project::init(&root.path().join("flow")).unwrap();
    let definition = Definition::load(&root.path().join("flow")).unwrap();
    let error = config.validate_workflow(&definition.workflow).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("connections.applications"));
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
        assert!(error
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("remove observationAuthorization"));
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
        .authorization
        .signing_key_ref =
        registry_platform_config::SecretReference::parse("secret:file/another-unavailable-key")
            .unwrap();
    assert_eq!(digest, config.binding_digest().unwrap());
    let audience = config.connections["applications"]
        .authorization
        .token_endpoint
        .as_str()
        .to_owned();
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization
        .client_assertion_audience = Some(audience);
    assert_eq!(digest, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization
        .client_assertion_audience = Some("http://127.0.0.1:8090".into());
    assert_ne!(digest, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization
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
        .authorization
        .task_authority
        .as_mut()
        .unwrap()
        .subject = "another-agent".into();
    assert_ne!(task, config.binding_digest().unwrap());
    config
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .task_authority = config.connections["applications"]
        .authorization
        .task_authority
        .clone();
    assert!(config.binding_digest().is_err());
}

#[test]
fn initialized_project_is_three_offline_checkable_files_and_never_overwrites() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("flow");
    project::init(&path).unwrap();
    let mut names = fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["functions.rhai", "runtime.yaml", "workflow.yaml"]);
    let config = RuntimeConfig::load(&path.canonicalize().unwrap().join("runtime.yaml")).unwrap();
    let definition = Definition::load(&path).unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    let explanation = definition.explain().unwrap();
    assert_eq!(explanation["networkAccess"], false);
    assert_eq!(explanation["secretResolution"], false);
    assert_eq!(explanation["steps"].as_array().unwrap().len(), 6);
    assert_eq!(explanation["limits"]["operations"], 100000);
    fs::write(path.join("functions.rhai"), CANARY).unwrap();
    assert!(project::init(&path).is_err());
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
    let pilot: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/pilot-runtime.yaml"
    ))
    .unwrap();
    assert!(validator.is_valid(&pilot));
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
        .authorization
        .task_authority = None;
    config
        .connections
        .get_mut("bookings")
        .unwrap()
        .observation_authorization = None;
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
    read_only["start"] = json!("metadata");
    read_only["connections"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| name == "catalogue");
    read_only["steps"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| matches!(name.as_str(), "metadata" | "skipped"));
    read_only["steps"]["metadata"]["next"] = json!("skipped");
    read_only["outcomes"]
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
fn caller_policy_flow_ids_use_the_workflow_name_grammar() {
    let original: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/pilot-runtime.yaml"
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
        document["deployment"]["authentication"]["policies"][0]["flows"] = json!([invalid]);
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
    document["deployment"]["authentication"]["policies"][0]["flows"] =
        json!(["a".repeat(64), "Retained_flow-1"]);
    load(&serde_norway::to_string(&document).unwrap()).unwrap();
}

#[test]
fn database_reference_requires_an_enabled_provider_without_resolving_values() {
    const REFERENCE_CANARY: &str = "UNDECLARED_DATABASE_REFERENCE_CANARY";
    let mut document: Value = yaml_value(include_str!(
        "../../../products/coordinator/examples/pilot-runtime.yaml"
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
    policies[0]["actions"] = json!(["start", "start"]);
    let error = refused(&document.to_string());
    assert_eq!(error.code, "config.duplicate-item");
    assert!(error
        .field
        .as_deref()
        .unwrap()
        .starts_with("/deployment/authentication/policies/0/actions"));
}
