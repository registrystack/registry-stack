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

const PICKER_DESCRIPTOR: &[u8] = br#"{
  "apiVersion":"id.registrystack.org/formats/platform/dev-picker-descriptor/v1alpha1",
  "kind":"PlatformDevPickerDescriptor",
  "runId":"0123456789abcdef0123456789abcdef",
  "persona":"holder",
  "origin":"http://127.0.0.1:41000",
  "sessionNamespace":"0123456789abcdef0123456789abcdef",
  "issuedAt":1700000000,
  "expiresAt":1700000600,
  "generationFile":"generation.json",
  "products":{
    "breg":{"url":"http://127.0.0.1:41001","resource":"urn:test:breg"},
    "casework":{"url":"http://127.0.0.1:41002","resource":"urn:test:casework"},
    "messaging":{"url":"http://127.0.0.1:41003","resource":"urn:test:messaging"}
  },
  "people":[{
    "selector":"abcdef0123456789abcdef0123456789",
    "label":"applicant",
    "subject":"person-one",
    "principal":"person-one",
    "clientId":"portal-client",
    "credentials":{
      "breg":{
        "tokenFile":"credential-0-breg.json",
        "profile":"applicant",
        "resource":"urn:test:breg",
        "audiences":["urn:test:breg"],
        "scopes":["breg:read"],
        "principalClaim":"registry_principal"
      },
      "casework":{
        "tokenFile":"credential-0-casework.json",
        "profile":"requester",
        "resource":"urn:test:casework",
        "audiences":["urn:test:casework","urn:test:breg"],
        "scopes":["casework:read"],
        "principalClaim":"registry_principal"
      }
    }
  }],
  "workloadConnectionFile":"../../python-workload/python-connection.json",
  "workloads":[{
    "name":"notices",
    "product":"messaging",
    "default":true,
    "url":"http://127.0.0.1:41003",
    "issuer":"https://issuer.example.test",
    "subject":"notice-service",
    "clientId":"notice-client",
    "profile":"service-sender",
    "resource":"urn:test:messaging",
    "scopes":["messaging:send"],
    "claims":{"registry_actor_kind":"service"}
  }]
}"#;

const PICKER_TOKEN: &[u8] = br#"{
  "apiVersion":"id.registrystack.org/formats/platform/dev-picker-token/v1alpha1",
  "kind":"PlatformDevPickerToken",
  "runId":"0123456789abcdef0123456789abcdef",
  "picker":"holder",
  "persona":"holder",
  "selector":"abcdef0123456789abcdef0123456789",
  "product":"breg",
  "issuer":"https://issuer.example.test",
  "subject":"person-one",
  "principal":"person-one",
  "clientId":"portal-client",
  "profile":"applicant",
  "resource":"urn:test:breg",
  "audiences":["urn:test:breg"],
  "scopes":["breg:read"],
  "principalClaim":"registry_principal",
  "generation":1,
  "issuedAt":1700000000,
  "expiresAt":1700000300,
  "runExpiresAt":1700000600,
  "token":"header.payload.signature"
}"#;

const PICKER_GENERATION: &[u8] = br#"{
  "apiVersion":"id.registrystack.org/formats/platform/dev-picker-generation/v1alpha1",
  "kind":"PlatformDevPickerGeneration",
  "status":"ready",
  "runId":"0123456789abcdef0123456789abcdef",
  "picker":"holder",
  "generation":1,
  "runExpiresAt":1700000600
}"#;

#[test]
fn registered_picker_readers_accept_representative_emitted_documents() {
    let descriptor = crate::read_dev_picker_descriptor("picker.json", PICKER_DESCRIPTOR)
        .expect("descriptor reads");
    assert_eq!(
        descriptor["people"][0]["credentials"]["breg"]["scopes"][0],
        "breg:read"
    );

    let token = crate::read_dev_picker_token("credential-0-breg.json", PICKER_TOKEN)
        .expect("ready token reads");
    assert_eq!(token["generation"], 1);

    let generation = crate::read_dev_picker_generation("generation.json", PICKER_GENERATION)
        .expect("generation reads");
    assert_eq!(generation["status"], "ready");
}

#[test]
fn picker_formats_are_typed_through_read_document_dispatch() {
    for (contents, file, api_version, kind) in [
        (
            PICKER_DESCRIPTOR,
            "picker.json",
            crate::DEV_PICKER_DESCRIPTOR_API_VERSION,
            crate::DEV_PICKER_DESCRIPTOR_KIND,
        ),
        (
            PICKER_TOKEN,
            "credential-0-breg.json",
            crate::DEV_PICKER_TOKEN_API_VERSION,
            crate::DEV_PICKER_TOKEN_KIND,
        ),
        (
            PICKER_GENERATION,
            "generation.json",
            crate::DEV_PICKER_GENERATION_API_VERSION,
            crate::DEV_PICKER_GENERATION_KIND,
        ),
    ] {
        read_checked(contents, file, api_version, kind).expect("registered format reads");
    }
}

#[test]
fn picker_descriptor_refuses_unknown_nested_members_and_duplicate_sets() {
    let mut descriptor: serde_json::Value =
        serde_json::from_slice(PICKER_DESCRIPTOR).expect("descriptor JSON");
    descriptor["people"][0]["credentials"]["breg"]["unexpected"] =
        serde_json::json!("value-canary");
    let bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
    let report = crate::read_dev_picker_descriptor("picker.json", &bytes)
        .expect_err("an unknown credential member refuses");
    assert_eq!(report.diagnostics()[0].code, "config.unknown-key");
    assert_eq!(
        report.diagnostics()[0].path,
        "/people/0/credentials/breg/unexpected"
    );
    assert!(!report.to_json_value().to_string().contains("value-canary"));

    descriptor["people"][0]["credentials"]["breg"]
        .as_object_mut()
        .expect("credential")
        .remove("unexpected");
    descriptor["people"][0]["credentials"]["breg"]["scopes"] =
        serde_json::json!(["breg:read", "breg:read"]);
    let bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
    let report = crate::read_dev_picker_descriptor("picker.json", &bytes)
        .expect_err("duplicate scopes refuse");
    assert_eq!(report.diagnostics()[0].code, "config.duplicate-item");
    assert_eq!(
        report.diagnostics()[0].path,
        "/people/0/credentials/breg/scopes/1"
    );
}

#[test]
fn picker_descriptor_refuses_explicit_null_and_unbounded_people() {
    let mut descriptor: serde_json::Value =
        serde_json::from_slice(PICKER_DESCRIPTOR).expect("descriptor JSON");
    descriptor["workloadConnectionFile"] = serde_json::Value::Null;
    let bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
    let report = crate::read_dev_picker_descriptor("picker.json", &bytes)
        .expect_err("explicit null refuses");
    assert_eq!(report.diagnostics()[0].code, "config.null-value");
    assert_eq!(report.diagnostics()[0].path, "/workloadConnectionFile");

    descriptor
        .as_object_mut()
        .expect("descriptor")
        .remove("workloadConnectionFile");
    descriptor["workloads"] = serde_json::json!([]);
    descriptor["people"] = serde_json::Value::Array(vec![descriptor["people"][0].clone(); 33]);
    let bytes = serde_json::to_vec(&descriptor).expect("descriptor JSON");
    let report = crate::read_dev_picker_descriptor("picker.json", &bytes)
        .expect_err("more than 32 people refuse");
    assert_eq!(report.diagnostics()[0].path, "/people");
}

#[test]
fn picker_readers_refuse_products_outside_each_supported_surface() {
    let mut descriptor: serde_json::Value =
        serde_json::from_slice(PICKER_DESCRIPTOR).expect("descriptor JSON");
    descriptor["people"][0]["credentials"]["messaging"] =
        descriptor["people"][0]["credentials"]["breg"].clone();
    let report = crate::read_dev_picker_descriptor(
        "picker.json",
        &serde_json::to_vec(&descriptor).expect("descriptor JSON"),
    )
    .expect_err("a person messaging credential refuses");
    assert_eq!(report.diagnostics()[0].code, "config.unknown-variant");
    assert_eq!(
        report.diagnostics()[0].path,
        "/people/0/credentials/messaging"
    );

    let mut descriptor: serde_json::Value =
        serde_json::from_slice(PICKER_DESCRIPTOR).expect("descriptor JSON");
    descriptor["workloads"][0]["product"] = serde_json::json!("casework");
    let report = crate::read_dev_picker_descriptor(
        "picker.json",
        &serde_json::to_vec(&descriptor).expect("descriptor JSON"),
    )
    .expect_err("a Casework service workload refuses");
    assert_eq!(report.diagnostics()[0].code, "config.unknown-variant");
    assert_eq!(report.diagnostics()[0].path, "/workloads/0/product");

    let mut token: serde_json::Value = serde_json::from_slice(PICKER_TOKEN).expect("token JSON");
    token["product"] = serde_json::json!("messaging");
    let report = crate::read_dev_picker_token(
        "credential-0-messaging.json",
        &serde_json::to_vec(&token).expect("token JSON"),
    )
    .expect_err("a person Messaging token refuses");
    assert_eq!(report.diagnostics()[0].code, "config.unknown-variant");
    assert_eq!(report.diagnostics()[0].path, "/product");
}

#[test]
fn picker_token_refuses_invalid_state_shapes_without_exposing_bearer() {
    let canary = "bearer-value-canary";
    let mut token: serde_json::Value = serde_json::from_slice(PICKER_TOKEN).expect("token JSON");
    token["status"] = serde_json::json!("stopped");
    token["token"] = serde_json::json!(canary);
    let bytes = serde_json::to_vec(&token).expect("token JSON");
    let report = crate::read_dev_picker_token("credential-0-breg.json", &bytes)
        .expect_err("token and stopped state together refuse");
    assert!(!report.to_json_value().to_string().contains(canary));

    token.as_object_mut().expect("token").remove("token");
    crate::read_dev_picker_token(
        "credential-0-breg.json",
        &serde_json::to_vec(&token).unwrap(),
    )
    .expect("stopped token metadata reads");
}

#[test]
fn picker_generation_refuses_zero_and_unknown_status() {
    let mut generation: serde_json::Value =
        serde_json::from_slice(PICKER_GENERATION).expect("generation JSON");
    generation["generation"] = serde_json::json!(0);
    let report = crate::read_dev_picker_generation(
        "generation.json",
        &serde_json::to_vec(&generation).unwrap(),
    )
    .expect_err("zero generation refuses");
    assert_eq!(report.diagnostics()[0].code, "config.out-of-range");
    assert_eq!(report.diagnostics()[0].path, "/generation");

    generation["generation"] = serde_json::json!(1);
    generation["status"] = serde_json::json!("retired-value-canary");
    let report = crate::read_dev_picker_generation(
        "generation.json",
        &serde_json::to_vec(&generation).unwrap(),
    )
    .expect_err("unknown status refuses");
    assert!(!report
        .to_json_value()
        .to_string()
        .contains("retired-value-canary"));
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
