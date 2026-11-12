use super::*;

const API_VERSION: &str = "id.registrystack.org/formats/platform/python-connection/v1alpha1";
const KIND: &str = "PlatformPythonConnection";

fn read(bytes: &[u8]) -> Result<serde_json::Value, yaml_core::Report> {
    read_checked(bytes, "connection.json", API_VERSION, KIND)
}

#[test]
fn valid_json_preserves_plain_json_values() {
    let document = read(
        br#"{
          "apiVersion":"id.registrystack.org/formats/platform/python-connection/v1alpha1",
          "kind":"PlatformPythonConnection",
          "service":"example-service",
          "audience":"service",
          "secretProviders":{"environment":{}},
          "bindings":[]
        }"#,
    )
    .expect("valid document");
    assert_eq!(document["service"], "example-service");
    assert_eq!(
        document["secretProviders"]["environment"],
        serde_json::json!({})
    );
    assert_eq!(document["bindings"], serde_json::json!([]));
}

#[test]
fn duplicate_json_keys_are_refused_with_both_positions() {
    let report = read(
        br#"{
          "apiVersion":"id.registrystack.org/formats/platform/python-connection/v1alpha1",
          "kind":"PlatformPythonConnection",
          "service":"first",
          "service":"second"
        }"#,
    )
    .expect_err("duplicate refuses");
    let diagnostic = &report.diagnostics()[0];
    assert_eq!(diagnostic.code, "yaml.duplicate-key");
    assert_eq!(
        diagnostic.source.as_ref().and_then(|source| source.line),
        Some(5)
    );
    assert_eq!(diagnostic.related[0].line, Some(4));
}

#[test]
fn reports_are_bounded_and_do_not_repeat_rejected_values() {
    let canary = "secret-canary-that-must-not-cross-the-reader";
    let input = format!(r#"{{"apiVersion":"{API_VERSION}","kind":"wrong-{canary}"}}"#);
    let report = read(input.as_bytes()).expect_err("wrong kind refuses");
    assert!(report.diagnostics().len() <= MAXIMUM_DIAGNOSTICS_PER_FILE);
    assert!(!report.to_json_value().to_string().contains(canary));
}

#[test]
fn diagnostic_floods_keep_only_the_shared_bounded_report() {
    let duplicate_members = (0..150)
        .map(|index| format!(r#""duplicate":"value-{index}""#))
        .collect::<Vec<_>>()
        .join(",");
    let input = format!(r#"{{"apiVersion":"{API_VERSION}","kind":"{KIND}",{duplicate_members}}}"#);
    let report = read(input.as_bytes()).expect_err("duplicates refuse");
    assert!(report.diagnostics().len() <= MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    assert_eq!(
        report
            .diagnostics()
            .last()
            .map(|diagnostic| diagnostic.code.as_str()),
        Some("config.too-many-problems")
    );
}

#[test]
fn format_parameter_bounds_are_checked_without_repeating_values() {
    assert_eq!(
        validate_file(&"x".repeat(MAXIMUM_FILE_BYTES + 1)),
        Err(Argument::File)
    );
    assert_eq!(
        validate_format_parameter(&"x".repeat(MAXIMUM_FORMAT_BYTES + 1), Argument::ApiVersion),
        Err(Argument::ApiVersion)
    );
    assert_eq!(
        validate_format_parameter("bad\nkind", Argument::Kind),
        Err(Argument::Kind)
    );
}

#[test]
fn registered_connection_reader_refuses_unknown_members_at_their_position() {
    let input = br#"{
      "apiVersion":"id.registrystack.org/formats/platform/python-connection/v1alpha1",
      "kind":"PlatformPythonConnection",
      "service":"example-service",
      "audience":"service",
      "secretProviders":{"environment":{}},
      "bindings":[],
      "unexpected":"value-canary"
    }"#;
    let report = crate::read_python_connection("connection.json", input)
        .expect_err("an unknown connection member refuses");
    assert_eq!(report.diagnostics()[0].code, "config.unknown-key");
    assert_eq!(report.diagnostics()[0].path, "/unexpected");
    assert_eq!(
        report.diagnostics()[0]
            .source
            .as_ref()
            .and_then(|source| source.line),
        Some(8)
    );
    assert!(!report.to_json_value().to_string().contains("value-canary"));
}

#[test]
fn registered_connection_reader_requires_type_for_the_credential_union() {
    let input = br#"{
      "apiVersion":"id.registrystack.org/formats/platform/python-connection/v1alpha1",
      "kind":"PlatformPythonConnection",
      "service":"example-service",
      "audience":"service",
      "secretProviders":{"environment":{}},
      "bindings":[{
        "name":"registry",
        "product":"breg",
        "url":"https://registry.example.test/",
        "default":true,
        "credential":{
          "kind":"private-key-jwt",
          "tokenEndpoint":"https://identity.example.test/token",
          "clientId":"service-1",
          "clientKeyRef":"secret:env/SERVICE_KEY",
          "resource":"urn:example:breg",
          "scopes":["registry.read"]
        }
      }]
    }"#;
    let report = crate::read_python_connection("connection.json", input)
        .expect_err("kind is not the credential discriminator");
    assert_eq!(report.diagnostics()[0].code, "config.missing-key");
    assert_eq!(report.diagnostics()[0].path, "/bindings/0/credential");
}

#[test]
fn registered_connection_reader_refuses_empty_authority_sets() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let connection = std::fs::read(
        root.join("products/platform/examples/python-composition/connection.example.json"),
    )
    .expect("connection example");
    let mut connection: serde_json::Value =
        serde_json::from_slice(&connection).expect("connection example JSON");
    connection["bindings"][0]["credential"]["scopes"] = serde_json::json!([]);
    let connection = serde_json::to_vec(&connection).expect("connection example JSON");
    let report = crate::read_python_connection("connection.example.json", &connection)
        .expect_err("an empty authority set refuses");
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.path == "/bindings/0/credential/scopes"));
}

#[test]
fn registered_readers_accept_the_committed_examples() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let connection = std::fs::read(
        root.join("products/platform/examples/python-composition/connection.example.json"),
    )
    .expect("connection example");
    let token =
        std::fs::read(root.join("products/platform/examples/dev-workload-token-stopped.json"))
            .expect("token example");
    crate::read_python_connection("connection.example.json", &connection)
        .expect("connection example reads");
    let token = crate::read_dev_workload_token("dev-workload-token-stopped.json", &token)
        .expect("token example reads");
    assert_eq!(token["claims"]["registry_actor_kind"], "service");
}

#[test]
fn registered_token_reader_refuses_wrong_types_without_repeating_the_token() {
    let input = br#"{
      "apiVersion":"id.registrystack.org/formats/platform/dev-workload-token/v1alpha1",
      "kind":"PlatformDevWorkloadToken",
      "runId":"run-1",
      "binding":"registry",
      "product":"breg",
      "issuer":"https://identity.example.test/",
      "subject":"service-1",
      "clientId":"service-1",
      "profile":"writer",
      "resource":"urn:example:breg",
      "scopes":["registry.write"],
      "claims":{"registry_actor_kind":"service"},
      "generation":"1",
      "issuedAt":1,
      "expiresAt":2,
      "runExpiresAt":3,
      "token":"value-canary"
    }"#;
    let report = crate::read_dev_workload_token("workload-registry.json", input)
        .expect_err("a quoted generation refuses");
    assert_eq!(report.diagnostics()[0].code, "config.expected-integer");
    assert_eq!(report.diagnostics()[0].path, "/generation");
    assert!(!report.to_json_value().to_string().contains("value-canary"));
}

#[test]
fn registered_token_reader_does_not_treat_null_as_omission() {
    let input = br#"{
      "apiVersion":"id.registrystack.org/formats/platform/dev-workload-token/v1alpha1",
      "kind":"PlatformDevWorkloadToken",
      "runId":"run-1",
      "binding":"registry",
      "product":"breg",
      "issuer":"https://identity.example.test/",
      "subject":"service-1",
      "clientId":"service-1",
      "profile":"writer",
      "resource":"urn:example:breg",
      "scopes":["registry.write"],
      "claims":{"registry_actor_kind":"service"},
      "generation":1,
      "issuedAt":1,
      "expiresAt":2,
      "runExpiresAt":3,
      "token":null
    }"#;
    let report = crate::read_dev_workload_token("workload-registry.json", input)
        .expect_err("an explicit null token refuses");
    assert_eq!(report.diagnostics()[0].path, "/token");
}

#[cfg(feature = "schema")]
#[test]
fn generated_schema_documents_match_the_committed_files() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (name, document) in crate::schema_documents() {
        let path = root.join("products/platform/schemas").join(name);
        let mut expected = serde_json::to_string_pretty(&document).expect("schema JSON");
        expected.push('\n');
        assert_eq!(
            std::fs::read_to_string(&path).expect("committed schema"),
            expected,
            "{} drifted",
            path.display()
        );
    }
}
