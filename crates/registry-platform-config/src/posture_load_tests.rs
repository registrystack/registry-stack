//! The loader and the offline check under a declared posture, with the shared
//! blocks that hold development-only settings.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use registry_platform_yaml::Severity;
use serde::Deserialize;

use crate::blocks::{
    plaintext_permitted_with, AuditKeyConfig, AuditKeyCustody, DatabaseConfig, DatabaseHost,
    DatabaseTransport, DatabaseTransportError, JwksSource, OidcIssuerConfig,
};
use crate::{
    DeclaredPosture, Gated, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope,
    DEFAULT_STAND_IN,
};

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const HEAD: &str =
    "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct Example {
    database: DatabaseConfig,
    authentication: Authentication,
    audit: Audit,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authentication {
    oidc: Oidc,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Oidc {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    provider: OidcIssuerConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct Audit {
    path: String,
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    key: AuditKeyConfig,
}

const SHARED_CODES: [&str; 3] = [
    "platform.posture.database-private-plaintext",
    "platform.posture.insecure-issuer-http",
    "platform.posture.generated-audit-key",
];

const SHARED_POINTERS: [&str; 3] = [
    "/database/transport",
    "/authentication/oidc/allowInsecureHttp",
    "/audit/hashKeyCustody",
];

/// A file holding every development-only setting the shared blocks have.
fn every_setting() -> String {
    format!(
        "{HEAD}database:\n  runtimeUrlRef: secret:env/DB_RUNTIME\n  migrationUrlRef: secret:env/DB_MIGRATION\n  transport: private-network-plaintext\nauthentication:\n  oidc:\n    issuer: http://issuer.example.test\n    audience: api\n    allowInsecureHttp: true\naudit:\n  path: /var/lib/audit\n  hashKeyRef: secret:env/AUDIT_KEY\n  hashKeyCustody: development-generated\n"
    )
}

/// The same file with every setting at a value valid in every posture.
fn no_setting() -> String {
    format!(
        "{HEAD}database:\n  runtimeUrlRef: secret:env/DB_RUNTIME\n  migrationUrlRef: secret:env/DB_MIGRATION\n  transport: verified-tls\nauthentication:\n  oidc:\n    issuer: https://issuer.example.test\n    audience: api\n    allowInsecureHttp: false\naudit:\n  path: /var/lib/audit\n  hashKeyRef: secret:env/AUDIT_KEY\n  hashKeyCustody: operator-provisioned\n"
    )
}

fn declared(posture: Posture) -> DeclaredPosture {
    DeclaredPosture {
        posture,
        source: PostureSource::Flag,
    }
}

fn parse(
    loader: &RuntimeConfigLoader,
    text: &str,
) -> Result<crate::LoadedRuntimeConfig<Example>, crate::RuntimeConfigError> {
    loader.parse_str::<Example>(text, |_| None)
}

#[test]
fn production_refuses_every_shared_development_setting_and_lists_each_with_its_pointer() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let error = parse(&loader, &every_setting()).expect_err("production refuses");
    let diagnostics = error.diagnostics();
    for (code, pointer) in SHARED_CODES.iter().zip(SHARED_POINTERS) {
        let found = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == *code)
            .unwrap_or_else(|| panic!("{code} is listed: {diagnostics:?}"));
        assert_eq!(found.path, pointer, "{code}");
        assert_eq!(found.severity, Severity::Error, "{code}");
        assert!(found.source.as_ref().unwrap().line.is_some(), "{code}");
    }
    assert_eq!(diagnostics.len(), 3, "{diagnostics:?}");
}

#[test]
fn a_decode_failure_and_the_settings_found_before_it_are_reported_together() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let text = every_setting().replace("audience: api\n", "audience: api\n    unknown: 1\n");
    let error = parse(&loader, &text).expect_err("production refuses");
    let codes: Vec<&str> = error
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert!(codes.contains(&"config.unknown-key"), "{codes:?}");
    assert!(
        codes.contains(&"platform.posture.database-private-plaintext"),
        "{codes:?}"
    );
}

#[test]
fn development_admits_the_settings_lists_them_and_yields_a_witness() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Development));
    let loaded = parse(&loader, &every_setting()).expect("development admits");
    assert_eq!(loaded.posture.posture(), Posture::Development);
    let witness = loaded.development.as_ref().expect("a witness");
    let listed: Vec<(&str, Option<&str>)> = loaded
        .posture
        .settings()
        .iter()
        .map(|found| (found.setting.code, found.pointer.as_deref()))
        .collect();
    for (code, pointer) in SHARED_CODES.iter().zip(SHARED_POINTERS) {
        assert!(
            listed.contains(&(*code, Some(pointer))),
            "{code}: {listed:?}"
        );
    }
    assert_eq!(listed.len(), 3);
    let warnings = loaded
        .posture
        .diagnostics(PathBuf::from("runtime.yaml").as_path());
    assert!(warnings
        .iter()
        .all(|diagnostic| diagnostic.severity == Severity::Warning));
    loaded
        .posture
        .decide(PathBuf::from("runtime.yaml").as_path())
        .unwrap();

    let database = &loaded.config.database;
    let transport = database.transport.as_ref().expect("written");
    assert_eq!(
        transport.get(Some(witness)).unwrap(),
        &DatabaseTransport::PrivateNetworkPlaintext
    );
    assert!(transport.get(None).is_err());
    assert_eq!(
        loaded
            .config
            .audit
            .key
            .hash_key_custody
            .get(Some(witness))
            .unwrap(),
        &AuditKeyCustody::DevelopmentGenerated
    );
}

#[test]
fn a_file_with_no_development_setting_loads_the_same_in_both_postures_and_only_development_holds_a_witness(
) {
    for posture in [Posture::Production, Posture::Development] {
        let loader = RuntimeConfigLoader::new(ENVELOPE, declared(posture));
        let loaded = parse(&loader, &no_setting()).expect("valid in every posture");
        assert!(loaded.posture.settings().is_empty(), "{posture:?}");
        assert_eq!(
            loaded.development.is_some(),
            posture == Posture::Development,
            "{posture:?}"
        );
    }
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    assert!(parse(&loader, &every_setting()).is_err());
}

#[test]
fn an_omitted_custody_is_operator_provisioned_and_an_omitted_transport_is_verified_tls() {
    let text = no_setting()
        .replace("  transport: verified-tls\n", "")
        .replace("  hashKeyCustody: operator-provisioned\n", "")
        .replace("    allowInsecureHttp: false\n", "");
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let loaded = parse(&loader, &text).expect("valid");
    assert!(loaded.posture.settings().is_empty());
    assert!(loaded.config.database.transport.is_none());
    assert_eq!(
        loaded.config.audit.key.hash_key_custody.get(None).unwrap(),
        &AuditKeyCustody::OperatorProvisioned
    );
    assert_eq!(
        serde_json::to_value(&loaded.config.audit.key).unwrap(),
        serde_json::json!({"hashKeyRef": "secret:env/AUDIT_KEY"}),
        "an omitted custody is not written back"
    );
}

#[test]
fn the_entry_point_without_a_posture_admits_what_it_always_admitted_and_reports_production() {
    let loader = RuntimeConfigLoader::new_without_posture(ENVELOPE);
    let loaded = parse(&loader, &every_setting()).expect("admitted, as before");
    assert_eq!(loaded.posture.posture(), Posture::Production);
    assert!(loaded.posture.settings().is_empty());
    assert!(loaded.development.is_none());
    assert!(
        loaded
            .config
            .authentication
            .oidc
            .provider
            .allow_insecure_http
    );
}

fn check_file(loader: &RuntimeConfigLoader, text: &str) -> crate::RuntimeFileCheck<Example> {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = directory.path().join("runtime.yaml");
    fs::write(&path, text).unwrap();
    loader.check_offline::<Example>(&path, true, |_| DEFAULT_STAND_IN)
}

#[test]
fn the_offline_check_in_production_decodes_the_file_and_reports_each_setting_as_an_error() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let check = check_file(&loader, &every_setting());
    assert!(check.loaded.is_some(), "product checks still run");
    assert_eq!(check.diagnostics.len(), 3, "{:?}", check.diagnostics);
    for (code, pointer) in SHARED_CODES.iter().zip(SHARED_POINTERS) {
        let found = check
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == *code)
            .unwrap_or_else(|| panic!("{code}: {:?}", check.diagnostics));
        assert_eq!(found.path, pointer);
        assert_eq!(found.severity, Severity::Error);
    }
    let report = check.report_with("example", Vec::new());
    assert_eq!(report.diagnostics().len(), 3);
}

#[test]
fn the_offline_check_in_development_reports_the_same_codes_as_warnings() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Development));
    let check = check_file(&loader, &every_setting());
    assert!(check.loaded.is_some());
    let codes: Vec<&str> = check
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert_eq!(codes.len(), 3, "{codes:?}");
    for code in SHARED_CODES {
        assert!(codes.contains(&code), "{code}: {codes:?}");
    }
    assert!(check
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.severity == Severity::Warning));
}

#[test]
fn the_offline_check_without_a_posture_adds_nothing() {
    let loader = RuntimeConfigLoader::new_without_posture(ENVELOPE);
    let check = check_file(&loader, &every_setting());
    assert!(check.loaded.is_some());
    assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
}

#[test]
fn a_decode_failure_in_a_check_carries_the_settings_found_before_it() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let text = every_setting().replace("audience: api\n", "audience: api\n    unknown: 1\n");
    let check = check_file(&loader, &text);
    assert!(check.loaded.is_none());
    let codes: Vec<&str> = check
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert!(codes.contains(&"config.unknown-key"), "{codes:?}");
    assert!(
        codes.contains(&"platform.posture.database-private-plaintext"),
        "{codes:?}"
    );
}

// The issuer check

/// One shared block read alone, through the shared reader.
fn read_block<T: serde::de::DeserializeOwned>(text: &str) -> T {
    use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader};
    const BLOCK: FormatSpec = FormatSpec {
        kind: "SharedRuntimeBlock",
        envelope: EnvelopeRule::Exempt {
            reason: "a shared runtime block read alone by its unit tests",
        },
        removed_keys: &[],
    };
    Reader::new("block.yaml")
        .decode::<T>(text.as_bytes(), &Expect::one(&BLOCK))
        .expect("the block decodes")
        .value
}

fn issuer(address: &str, allow_insecure_http: bool) -> OidcIssuerConfig {
    read_block(&format!(
        "issuer: {address}\naudience: api\nallowInsecureHttp: {allow_insecure_http}\n"
    ))
}

#[test]
fn a_loopback_http_issuer_needs_no_setting_and_a_remote_one_needs_the_development_flag() {
    for loopback in [
        "http://127.0.0.1:8082",
        "http://localhost:8082",
        "http://[::1]:8082",
    ] {
        issuer(loopback, false)
            .check("authentication.oidc")
            .unwrap_or_else(|error| panic!("{loopback}: {error}"));
    }
    issuer("http://issuer.example.test", false)
        .check("authentication.oidc")
        .expect_err("remote plain http is refused without the flag");
    issuer("http://issuer.example.test", true)
        .check("authentication.oidc")
        .expect("the flag admits it; the posture decision refuses it in production");
    issuer("https://issuer.example.test", false)
        .check("authentication.oidc")
        .expect("https");
}

#[test]
fn the_check_without_a_posture_keeps_the_loopback_argument() {
    let loopback = issuer("http://127.0.0.1:8082", false);
    loopback
        .check_without_posture("authentication.oidc", true)
        .expect("admitted when asked");
    loopback
        .check_without_posture("authentication.oidc", false)
        .expect_err("refused when not asked");
}

// Database transport

fn database(transport: Option<&str>, test_only_plaintext: bool) -> DatabaseConfig {
    let mut text = String::from(
        "runtimeUrlRef: secret:env/DB_RUNTIME\nmigrationUrlRef: secret:env/DB_MIGRATION\n",
    );
    if let Some(transport) = transport {
        text.push_str(&format!("transport: {transport}\n"));
    }
    if test_only_plaintext {
        text.push_str("testOnlyPlaintext: true\n");
    }
    read_block(&text)
}

fn resolve(name: &str) -> std::io::Result<Vec<IpAddr>> {
    match name {
        "db.internal" => Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]),
        "db.mixed" => Ok(vec![
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        ]),
        "db.example.com" => Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        _ => Err(std::io::Error::other("no such name")),
    }
}

fn tcp(host: &str) -> Vec<DatabaseHost> {
    vec![DatabaseHost::Tcp(host.to_owned())]
}

#[test]
fn plaintext_permitted_answers_each_host_for_each_transport() {
    use DatabaseTransport::{LoopbackPlaintext, PrivateNetworkPlaintext, VerifiedTls};
    let witness_holder = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Development))
        .parse_str::<Example>(&every_setting(), |_| None)
        .unwrap();
    let witness = witness_holder.development.as_ref();

    let hosts: Vec<(&str, Vec<DatabaseHost>)> = vec![
        ("socket", vec![DatabaseHost::Unix]),
        ("127.0.0.1", tcp("127.0.0.1")),
        ("::1", tcp("::1")),
        ("[::1]", tcp("[::1]")),
        ("localhost", tcp("localhost")),
        ("10.0.0.5", tcp("10.0.0.5")),
        ("172.16.0.1", tcp("172.16.0.1")),
        ("192.168.1.1", tcp("192.168.1.1")),
        ("fd00::1", tcp("fd00::1")),
        ("db.internal", tcp("db.internal")),
        ("db.mixed", tcp("db.mixed")),
        ("db.example.com", tcp("db.example.com")),
        ("172.32.0.1", tcp("172.32.0.1")),
        ("8.8.8.8", tcp("8.8.8.8")),
        ("2001:db8::1", tcp("2001:db8::1")),
        ("unresolvable", tcp("unresolvable")),
    ];
    // (host, loopback-plaintext permits, private-network-plaintext permits)
    let expected = [
        ("socket", true, true),
        ("127.0.0.1", true, true),
        ("::1", true, true),
        ("[::1]", true, true),
        ("localhost", true, true),
        ("10.0.0.5", false, true),
        ("172.16.0.1", false, true),
        ("192.168.1.1", false, true),
        ("fd00::1", false, true),
        ("db.internal", false, true),
        ("db.mixed", false, false),
        ("db.example.com", false, false),
        ("172.32.0.1", false, false),
        ("8.8.8.8", false, false),
        ("2001:db8::1", false, false),
        ("unresolvable", false, false),
    ];
    for ((name, hosts), (expected_name, loopback, private)) in hosts.iter().zip(expected) {
        assert_eq!(*name, expected_name);
        for (transport, permitted) in [
            ("loopback-plaintext", loopback),
            ("private-network-plaintext", private),
        ] {
            let config = database(Some(transport), false);
            let answer = plaintext_permitted_with(&config, hosts, witness, &resolve);
            assert_eq!(answer.is_ok(), permitted, "{name} under {transport}");
            if !permitted {
                assert!(
                    matches!(answer, Err(DatabaseTransportError::HostMismatch(_))),
                    "{name} under {transport}: {answer:?}"
                );
            }
        }
        // `verified-tls`, written or omitted, takes every host.
        for transport in [Some("verified-tls"), None] {
            let config = database(transport, false);
            assert_eq!(
                plaintext_permitted_with(&config, hosts, witness, &resolve),
                Ok(VerifiedTls),
                "{name}"
            );
        }
    }
    let config = database(Some("loopback-plaintext"), false);
    assert_eq!(
        plaintext_permitted_with(&config, &[DatabaseHost::Unix], None, &resolve),
        Ok(LoopbackPlaintext)
    );
    let config = database(Some("private-network-plaintext"), false);
    assert_eq!(
        plaintext_permitted_with(&config, &tcp("10.0.0.5"), witness, &resolve),
        Ok(PrivateNetworkPlaintext)
    );
}

#[test]
fn a_private_network_transport_is_unreadable_without_the_witness() {
    let config = database(Some("private-network-plaintext"), false);
    let answer = plaintext_permitted_with(&config, &tcp("10.0.0.5"), None, &resolve);
    assert!(
        matches!(answer, Err(DatabaseTransportError::DevelopmentOnly(_))),
        "{answer:?}"
    );
    assert_eq!(
        answer.unwrap_err().code(),
        "platform.posture.database-private-plaintext"
    );
}

#[test]
fn a_transport_beside_test_only_plaintext_is_a_conflict_in_every_build() {
    let both = database(Some("loopback-plaintext"), true);
    for test_build in [false, true] {
        assert_eq!(
            both.check(test_build),
            Err(DatabaseTransportError::Conflict),
            "{test_build}"
        );
    }
    assert_eq!(
        DatabaseTransportError::Conflict.code(),
        "platform.database.transport-conflict"
    );
}

#[test]
fn test_only_plaintext_is_refused_outside_test_builds() {
    let config = database(None, true);
    assert_eq!(
        config.check(false),
        Err(DatabaseTransportError::TestOnlyPlaintext)
    );
    assert_eq!(config.check(true), Ok(()));
    let error = DatabaseTransportError::TestOnlyPlaintext;
    assert_eq!(error.code(), "platform.database.test-only-plaintext");
    assert_eq!(
        error.to_string(),
        "database.testOnlyPlaintext is accepted only by test builds"
    );
    assert_eq!(
        error.suggested_action(),
        "Remove it, and set database.transport for a plaintext connection on the same host."
    );
    assert_eq!(database(None, false).check(false), Ok(()));
}

/// A file whose issuer reads its keys from a test issuer.
fn test_issuer_file() -> String {
    format!(
        "{HEAD}database:\n  runtimeUrlRef: secret:env/DB_RUNTIME\n  migrationUrlRef: secret:env/DB_MIGRATION\nauthentication:\n  oidc:\n    issuer: https://issuer.example.test\n    audience: api\n    jwksSource:\n      type: test-issuer\n      documentRef: secret:env/TEST_JWKS\naudit:\n  path: /var/lib/audit\n  hashKeyRef: secret:env/AUDIT_KEY\n"
    )
}

#[test]
fn production_refuses_a_test_issuer_with_its_code_and_pointer() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Production));
    let error = parse(&loader, &test_issuer_file()).expect_err("production refuses");
    let diagnostics = error.diagnostics();
    let found = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.posture.test-issuer")
        .unwrap_or_else(|| panic!("the test issuer is listed: {diagnostics:?}"));
    assert_eq!(found.path, "/authentication/oidc/jwksSource");
    assert_eq!(found.severity, Severity::Error);
    assert!(found.source.as_ref().unwrap().line.is_some());
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
}

#[test]
fn development_admits_a_test_issuer_lists_it_and_the_witness_reads_it() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Development));
    let loaded = parse(&loader, &test_issuer_file()).expect("development admits");
    let listed: Vec<(&str, Option<&str>)> = loaded
        .posture
        .settings()
        .iter()
        .map(|found| (found.setting.code, found.pointer.as_deref()))
        .collect();
    assert_eq!(
        listed,
        [(
            "platform.posture.test-issuer",
            Some("/authentication/oidc/jwksSource")
        )]
    );
    let witness = loaded.development.as_ref().expect("a witness");
    let source = &loaded.config.authentication.oidc.provider.jwks_source;
    assert_eq!(source.document_ref(), Some("secret:env/TEST_JWKS"));
    let gated = Gated::everywhere(JwksSource::default()).expect("discovery is valid everywhere");
    assert!(gated.get(None).is_ok());
    let gated = Gated::for_tests(source.clone());
    assert_eq!(
        gated.get(None).unwrap_err().setting.code,
        "platform.posture.test-issuer"
    );
    assert_eq!(gated.get(Some(witness)).unwrap(), source);
}

#[test]
fn the_transitional_loader_reads_a_test_issuer_like_static() {
    let loader = RuntimeConfigLoader::new_without_posture(ENVELOPE);
    let loaded = parse(&loader, &test_issuer_file()).expect("the transitional loader admits");
    assert_eq!(loaded.posture.posture(), Posture::Production);
    assert!(loaded.posture.settings().is_empty());
    let from_static = test_issuer_file().replace("type: test-issuer", "type: static");
    let loaded_static = parse(&loader, &from_static).expect("static loads");
    assert_eq!(
        loaded
            .config
            .authentication
            .oidc
            .provider
            .jwks_source
            .document_ref(),
        loaded_static
            .config
            .authentication
            .oidc
            .provider
            .jwks_source
            .document_ref()
    );
}

#[test]
fn an_unknown_member_beside_a_test_issuer_is_refused() {
    let loader = RuntimeConfigLoader::new(ENVELOPE, declared(Posture::Development));
    let text = test_issuer_file().replace(
        "      documentRef: secret:env/TEST_JWKS\n",
        "      documentRef: secret:env/TEST_JWKS\n      uri: https://issuer.example.test/jwks\n",
    );
    let error = parse(&loader, &text).expect_err("an unknown member");
    assert!(
        error
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "config.unknown-key"),
        "{:?}",
        error.diagnostics()
    );
}
