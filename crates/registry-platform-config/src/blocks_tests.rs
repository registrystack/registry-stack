use super::*;
use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader, Report};

/// One shared block read alone, through the shared reader a runtime file's
/// members are read with, so these tests see what an operator sees.
const BLOCK: FormatSpec = FormatSpec {
    kind: "SharedRuntimeBlock",
    envelope: EnvelopeRule::Exempt {
        reason: "a shared runtime block read alone by its unit tests",
    },
    removed_keys: &[],
};

fn read_block<T: serde::de::DeserializeOwned>(yaml: &str) -> Result<T, Report> {
    Reader::new("block.yaml")
        .decode::<T>(yaml.as_bytes(), &Expect::one(&BLOCK))
        .map(|decoded| decoded.value)
}

fn codes(report: &Report) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

fn providers(yaml: &str) -> SecretProvidersConfig {
    read_block(yaml).expect("providers parse")
}

#[test]
fn secret_providers_must_enable_at_least_one_provider_with_an_absolute_root() {
    let error = providers("{}").check().expect_err("none refuses");
    assert_eq!(error.kind(), ConfigBlockErrorKind::NoSecretProvider);
    assert_eq!(error.field(), "secretProviders");

    let error = providers("file: {root: relative/secrets}")
        .check()
        .expect_err("relative root refuses");
    assert_eq!(error.kind(), ConfigBlockErrorKind::RelativePath);
    assert_eq!(error.field(), "secretProviders.file.root");

    providers("environment: {}").check().expect("env only");
    providers("file: {root: /run/secrets}\nenvironment: {}")
        .check()
        .expect("both");
    assert!(read_block::<SecretProvidersConfig>("environment: {x: 1}").is_err());
}

#[test]
fn a_reference_must_be_exact_and_its_provider_enabled() {
    let file_only = providers("file: {root: /run/secrets}");
    file_only
        .check_reference("audit.hashKeyRef", "secret:file/audit-key")
        .expect("file reference");
    let error = file_only
        .check_reference("audit.hashKeyRef", "secret:env/AUDIT_KEY")
        .expect_err("env disabled");
    assert_eq!(error.kind(), ConfigBlockErrorKind::SecretProviderDisabled);
    assert!(error.to_string().contains("secretProviders.environment"));

    let error = file_only
        .check_reference("audit.hashKeyRef", "plaintext-literal-key")
        .expect_err("invalid");
    assert_eq!(error.kind(), ConfigBlockErrorKind::InvalidSecretReference);
    assert!(!error.to_string().contains("plaintext-literal-key"));
}

#[test]
fn the_resolver_enables_exactly_the_declared_providers() {
    let resolver = providers("environment: {}").resolver().expect("resolver");
    assert!(matches!(
        resolver.resolve("secret:file/x"),
        Err(SecretError::ProviderDisabled)
    ));
}

#[test]
fn database_debug_redacts_every_reference() {
    let database: DatabaseConfig = read_block(
        "runtimeUrlRef: secret:env/RUNTIME_URL\nmigrationUrlRef: secret:env/MIGRATION_URL\ntrustedRootCertificateRef: secret:file/ca",
    )
    .expect("database parses");
    let rendered = format!("{database:?}");
    assert!(!rendered.contains("secret:"), "{rendered}");
    assert_eq!(
        database.references(),
        [
            ("database.runtimeUrlRef", "secret:env/RUNTIME_URL"),
            ("database.migrationUrlRef", "secret:env/MIGRATION_URL"),
            ("database.trustedRootCertificateRef", "secret:file/ca"),
        ]
    );
}

#[test]
fn a_discovery_jwks_source_refuses_the_members_of_the_other_types() {
    for text in [
        "type: discovery\nuri: https://keys.example.test/jwks",
        "type: discovery\ndocumentRef: secret:file/jwks",
    ] {
        let error =
            read_block::<JwksSource>(text).expect_err("a discovery source carries no other member");
        assert_eq!(codes(&error), ["config.unknown-key"], "{error}");
    }
    let discovery: JwksSource = read_block("type: discovery").unwrap();
    assert_eq!(discovery, JwksSource::Discovery {});
}

#[test]
fn a_jwks_source_refuses_a_missing_or_unknown_type() {
    for text in ["uri: https://keys.example.test/jwks", "type: remote"] {
        assert!(read_block::<JwksSource>(text).is_err(), "{text}");
    }
}

#[test]
fn a_jwks_source_tagged_by_kind_is_refused() {
    for text in [
        "kind: discovery",
        "kind: uri\nuri: https://keys.example.test/jwks",
        "kind: static\ndocumentRef: secret:file/jwks",
    ] {
        let error = read_block::<JwksSource>(text).expect_err("the tag is spelled type");
        assert!(!error.to_string().contains("keys.example.test"), "{error}");
        assert!(!error.to_string().contains("secret:file/jwks"), "{error}");
    }
}

#[test]
fn jwks_source_has_three_types_and_defaults_to_discovery() {
    assert_eq!(JwksSource::default(), JwksSource::Discovery {});
    let uri: JwksSource = read_block("type: uri\nuri: https://issuer.example.test/jwks").unwrap();
    assert_eq!(uri.uri(), Some("https://issuer.example.test/jwks"));
    uri.check("authentication.oidc.jwksSource", false)
        .expect("https uri");
    let static_source: JwksSource =
        read_block("type: static\ndocumentRef: secret:file/jwks").unwrap();
    assert_eq!(static_source.document_ref(), Some("secret:file/jwks"));
    assert!(read_block::<JwksSource>("type: static\nuri: x").is_err());

    for (uri, loopback) in [
        ("http://issuer.example.test/jwks", true),
        ("http://127.0.0.1:1/jwks", false),
    ] {
        let source = JwksSource::Uri {
            uri: Url::new(uri).unwrap(),
        };
        let error = source
            .check("authentication.oidc.jwksSource", loopback)
            .expect_err("refused uri");
        assert_eq!(error.field(), "authentication.oidc.jwksSource.uri");
    }
    JwksSource::Uri {
        uri: Url::new("http://127.0.0.1:1/jwks").unwrap(),
    }
    .check("authentication.oidc.jwksSource", true)
    .expect("supervised loopback");
    for uri in ["https://user:pass@issuer.example.test/jwks", "not a url"] {
        let report =
            read_block::<JwksSource>(&serde_json::json!({"type": "uri", "uri": uri}).to_string())
                .expect_err("invalid URL is refused before key source policy");
        assert_eq!(report.diagnostics()[0].path, "/uri");
    }
}

#[test]
fn issuer_and_jwks_uri_are_checked_urls_when_read() {
    for text in [
        "https://issuer.example/a\\b".to_owned(),
        "https://iss\u{200b}uer.example".to_owned(),
        "https://issuer\u{3002}example".to_owned(),
        format!("https://issuer.example/{}", "x".repeat(2048)),
        " https://issuer.example".to_owned(),
    ] {
        let uri = serde_json::json!({"type": "uri", "uri": text}).to_string();
        let report = read_block::<JwksSource>(&uri).expect_err("typed JWKS URL");
        assert_eq!(report.diagnostics()[0].path, "/uri");
        assert_eq!(report.diagnostics()[0].code, "config.invalid-value");
        assert!(!report.to_string().contains(&text));
        let issuer = serde_json::json!({"issuer": text, "audience": "api"}).to_string();
        let report = read_block::<OidcIssuerConfig>(&issuer).expect_err("typed issuer URL");
        assert_eq!(report.diagnostics()[0].path, "/issuer");
        assert_eq!(report.diagnostics()[0].code, "config.invalid-value");
        assert!(!report.to_string().contains(&text));
    }
    for text in [
        "https://Issuer.Example/realms/pilot",
        "https://xn--caf-dma.example/realms/pilot",
        "https://[2001:db8::1]/realms/pilot",
    ] {
        let source: JwksSource =
            read_block(&serde_json::json!({"type": "uri", "uri": text}).to_string())
                .expect("ordinary JWKS URL");
        source
            .check("authentication.oidc.jwksSource", false)
            .unwrap();
        assert_eq!(source.uri(), Some(text));
        let issuer: OidcIssuerConfig =
            read_block(&serde_json::json!({"issuer": text, "audience": "api"}).to_string())
                .expect("ordinary issuer URL");
        issuer.check("authentication.oidc", false).unwrap();
        assert_eq!(issuer.issuer.as_str(), text);
    }
}

#[test]
fn package_root_is_absolute_and_the_pin_is_a_sha256_label() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let package = PackageConfig {
        root: PathBuf::from("/srv/package"),
        expected_digest: Some(digest.clone()),
    };
    package.check().expect("valid package");
    package.verify_digest(&digest).expect("matches");

    let other = format!("sha256:{}", "b".repeat(64));
    let mismatch = package.verify_digest(&other).expect_err("mismatch");
    assert_eq!(
        mismatch.to_string(),
        format!(
            "package.expectedDigest is {digest} but the package at package.root is {other}; \
             deploy the pinned package or update package.expectedDigest"
        )
    );

    PackageConfig {
        root: PathBuf::from("/srv/package"),
        expected_digest: None,
    }
    .verify_digest(&other)
    .expect("no pin, no check");

    let error = PackageConfig {
        root: PathBuf::from("package"),
        expected_digest: None,
    }
    .check()
    .expect_err("relative");
    assert_eq!(error.field(), "package.root");

    for bad in [
        "sha256:ABC",
        "sha512:aa",
        &format!("sha256:{}", "A".repeat(64)),
    ] {
        let error = PackageConfig {
            root: PathBuf::from("/srv/package"),
            expected_digest: Some(bad.to_owned()),
        }
        .check()
        .expect_err("bad digest");
        assert_eq!(error.kind(), ConfigBlockErrorKind::InvalidDigest);
    }
}

#[test]
fn listener_bind_is_an_ip_socket_address() {
    let listener: ListenerConfig = read_block("bind: \"[::1]:8080\"").unwrap();
    assert_eq!(listener.bind.socket_addr().port(), 8080);
    for bad in ["localhost:8080", "127.0.0.1", "8080"] {
        let error =
            read_block::<ListenerConfig>(&format!("bind: \"{bad}\"")).expect_err("refused bind");
        assert!(error
            .to_string()
            .contains("expected host:port with an IP address host"));
    }
    assert!(read_block::<ListenerConfig>("address: 127.0.0.1:1").is_err());

    let padded = |port: &str| {
        let width = MAX_LISTENER_BIND_CHARACTERS - "127.0.0.1:".len();
        format!("bind: \"127.0.0.1:{port:0>width$}\"")
    };
    read_block::<ListenerConfig>(&padded("80")).expect("bound length");
    let overlong = padded("80").replacen(":0", ":00", 1);
    let error = read_block::<ListenerConfig>(&overlong).expect_err("overlong bind");
    assert!(error
        .to_string()
        .contains("expected host:port with an IP address host"));
}

#[test]
fn private_listener_follows_the_declared_boundary() {
    let listener = |bind: &str, tls: TlsTermination, exposure: ListenerNetworkExposure| {
        PrivateListenerConfig {
            bind: bind.parse().unwrap(),
            tls_termination: tls,
            network_exposure: exposure,
        }
        .is_valid()
    };
    use ListenerNetworkExposure::{ContainerPrivate, PrivateAddress};
    use TlsTermination::{DevelopmentLoopback, OperatorControlledUpstream};
    assert!(listener("127.0.0.1:1", DevelopmentLoopback, PrivateAddress));
    assert!(!listener("10.0.0.1:1", DevelopmentLoopback, PrivateAddress));
    assert!(!listener(
        "127.0.0.1:1",
        DevelopmentLoopback,
        ContainerPrivate
    ));
    assert!(listener(
        "10.0.0.1:1",
        OperatorControlledUpstream,
        PrivateAddress
    ));
    assert!(listener(
        "[fd00::1]:1",
        OperatorControlledUpstream,
        PrivateAddress
    ));
    assert!(!listener(
        "0.0.0.0:1",
        OperatorControlledUpstream,
        PrivateAddress
    ));
    assert!(listener(
        "0.0.0.0:1",
        OperatorControlledUpstream,
        ContainerPrivate
    ));
    assert!(!listener(
        "8.8.8.8:1",
        OperatorControlledUpstream,
        ContainerPrivate
    ));
    assert!(!listener(
        "224.0.0.1:1",
        OperatorControlledUpstream,
        ContainerPrivate
    ));
}

#[test]
fn sha256_label_shape() {
    assert!(is_sha256_label(&crate::sha256_uri(b"x")));
    assert!(!is_sha256_label("sha256:"));
}

#[test]
fn blocks_serialize_back_to_the_form_they_were_read_from() {
    let providers: SecretProvidersConfig =
        read_block("file: {root: /run/secrets}\nenvironment: {}").unwrap();
    let package: PackageConfig = read_block("root: /srv/package").unwrap();
    let listener: ListenerConfig = read_block("bind: \"[::1]:8080\"").unwrap();
    let jwks: JwksSource = read_block("type: uri\nuri: https://issuer.example.test/jwks").unwrap();
    assert_eq!(
        serde_json::to_value(&providers).unwrap(),
        serde_json::json!({"file": {"root": "/run/secrets"}, "environment": {}})
    );
    assert_eq!(
        serde_json::to_value(&package).unwrap(),
        serde_json::json!({"root": "/srv/package"})
    );
    assert_eq!(
        serde_json::to_value(listener).unwrap(),
        serde_json::json!({"bind": "[::1]:8080"})
    );
    assert_eq!(
        serde_json::to_value(&jwks).unwrap(),
        serde_json::json!({"type": "uri", "uri": "https://issuer.example.test/jwks"})
    );
    assert_eq!(
        serde_json::to_value(JwksSource::Discovery {}).unwrap(),
        serde_json::json!({"type": "discovery"})
    );
    for (value, text) in [
        (serde_json::to_value(&providers).unwrap(), "providers"),
        (serde_json::to_value(&package).unwrap(), "package"),
    ] {
        assert!(value.is_object(), "{text}");
    }
    assert_eq!(
        serde_json::from_value::<SecretProvidersConfig>(serde_json::to_value(&providers).unwrap())
            .unwrap(),
        providers
    );
}

/// A product audit block embedding the shared key beside its own sink setting.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductAudit {
    path: String,
    #[serde(flatten)]
    key: AuditKeyConfig,
}

#[test]
fn the_audit_key_embeds_beside_product_members_and_redacts_its_reference() {
    let audit: ProductAudit = read_block("path: /var/lib/audit\nhashKeyRef: secret:file/audit-key")
        .expect("embedded audit key parses");
    assert_eq!(audit.path, "/var/lib/audit");
    assert_eq!(audit.key.hash_key_ref.as_str(), "secret:file/audit-key");
    assert!(!format!("{audit:?}").contains("audit-key"), "{audit:?}");

    for (text, reason) in [
        (
            "path: /var/lib/audit\nhashKeyRef: secret:file/audit-key\nother: 1",
            "an unknown member beside the embedded key",
        ),
        (
            "path: /var/lib/audit\nhashSecretRef: secret:file/audit-key",
            "the key under another name",
        ),
        ("path: /var/lib/audit", "no key"),
    ] {
        assert!(
            read_block::<ProductAudit>(text).is_err(),
            "{reason} must be refused"
        );
    }

    let error =
        read_block::<ProductAudit>("path: /var/lib/audit\nhashKeyRef: plaintext-literal-key")
            .expect_err("a literal is not a reference");
    assert!(
        !error.to_string().contains("plaintext-literal-key"),
        "{error}"
    );
}

#[test]
fn the_audit_key_names_an_enabled_provider() {
    let key: AuditKeyConfig = read_block("hashKeyRef: secret:env/AUDIT_KEY").unwrap();
    key.check(&providers("environment: {}"))
        .expect("enabled provider");
    let error = key
        .check(&providers("file: {root: /run/secrets}"))
        .expect_err("disabled provider");
    assert_eq!(error.kind(), ConfigBlockErrorKind::SecretProviderDisabled);
    assert_eq!(error.field(), "audit.hashKeyRef");
    assert_eq!(
        serde_json::to_value(&key).unwrap(),
        serde_json::json!({"hashKeyRef": "secret:env/AUDIT_KEY"})
    );
}

/// A product OIDC block embedding the shared issuer beside its own members.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductOidc {
    #[serde(flatten)]
    issuer: OidcIssuerConfig,
    token_types: Vec<String>,
}

#[test]
fn the_oidc_issuer_embeds_beside_product_members() {
    let oidc: ProductOidc = read_block(
        "issuer: https://issuer.example.test\naudience: urn:example:api\n\
         jwksSource: {type: uri, uri: https://issuer.example.test/jwks}\ntokenTypes: [at+jwt]",
    )
    .expect("embedded issuer parses");
    assert_eq!(oidc.issuer.issuer.as_str(), "https://issuer.example.test");
    assert_eq!(oidc.issuer.audience, "urn:example:api");
    assert_eq!(
        oidc.issuer.jwks_source.uri(),
        Some("https://issuer.example.test/jwks")
    );
    assert_eq!(oidc.token_types, ["at+jwt"]);

    let defaulted: ProductOidc = read_block(
        "issuer: https://issuer.example.test\naudience: urn:example:api\ntokenTypes: []",
    )
    .unwrap();
    assert_eq!(defaulted.issuer.jwks_source, JwksSource::Discovery {});

    for (text, reason) in [
        (
            "issuer: https://issuer.example.test\naudience: a\ntokenTypes: []\nother: 1",
            "an unknown member",
        ),
        (
            "issuer: https://issuer.example.test\naudiences: [a]\ntokenTypes: []",
            "a plural audience",
        ),
        (
            "issuer: https://issuer.example.test\naudience: a\njwksUri: https://issuer.example.test/jwks\ntokenTypes: []",
            "a bare JWKS URI",
        ),
    ] {
        assert!(
            read_block::<ProductOidc>(text).is_err(),
            "{reason} must be refused"
        );
    }
}

fn issuer(issuer: &str, audience: &str, jwks_source: JwksSource) -> OidcIssuerConfig {
    OidcIssuerConfig {
        issuer: Url::new(issuer).unwrap(),
        audience: audience.to_owned(),
        jwks_source,
    }
}

#[test]
fn the_oidc_issuer_is_an_https_url_and_the_audience_is_bounded_text() {
    let field = "authentication.oidc";
    issuer(
        "https://issuer.example.test",
        "urn:example:api",
        JwksSource::default(),
    )
    .check(field, false)
    .expect("https issuer");
    issuer("http://127.0.0.1:8082", "api", JwksSource::default())
        .check(field, true)
        .expect("supervised loopback issuer");

    for (candidate, loopback, expected_field) in [
        (
            issuer("http://issuer.example.test", "api", JwksSource::default()),
            true,
            "authentication.oidc.issuer",
        ),
        (
            issuer("http://127.0.0.1:8082", "api", JwksSource::default()),
            false,
            "authentication.oidc.issuer",
        ),
        (
            issuer(
                "https://issuer.example.test#fragment",
                "api",
                JwksSource::default(),
            ),
            false,
            "authentication.oidc.issuer",
        ),
        (
            issuer("https://issuer.example.test", "", JwksSource::default()),
            false,
            "authentication.oidc.audience",
        ),
        (
            issuer("https://issuer.example.test", "a\nb", JwksSource::default()),
            false,
            "authentication.oidc.audience",
        ),
        (
            issuer(
                "https://issuer.example.test",
                &"a".repeat(MAX_OIDC_AUDIENCE_CHARACTERS + 1),
                JwksSource::default(),
            ),
            false,
            "authentication.oidc.audience",
        ),
        (
            issuer(
                "https://issuer.example.test",
                "api",
                JwksSource::Uri {
                    uri: Url::new("http://keys.example.test/jwks").unwrap(),
                },
            ),
            false,
            "authentication.oidc.jwksSource.uri",
        ),
    ] {
        let error = candidate
            .check(field, loopback)
            .expect_err("refused issuer");
        assert_eq!(error.field(), expected_field, "{error}");
        assert!(!error.to_string().contains("user:pass"), "{error}");
    }
    for text in [
        "https://user:pass@issuer.example.test",
        "issuer.example.test",
    ] {
        let report = read_block::<OidcIssuerConfig>(
            &serde_json::json!({"issuer": text, "audience": "api"}).to_string(),
        )
        .expect_err("invalid URL is refused before issuer policy");
        assert_eq!(report.diagnostics()[0].path, "/issuer");
        assert!(!report.to_string().contains("user:pass"));
    }
}

#[test]
fn an_oidc_issuer_with_a_query_is_refused_without_echoing_it() {
    let field = "authentication.oidc";
    issuer(
        "https://issuer.example.test/realms/pilot",
        "api",
        JwksSource::default(),
    )
    .check(field, false)
    .expect("an issuer with a path");
    for candidate in [
        "https://issuer.example.test/realms/pilot?tenant=query-canary",
        "https://issuer.example.test/?",
    ] {
        let error = issuer(candidate, "api", JwksSource::default())
            .check(field, false)
            .expect_err("an issuer with a query is refused");
        assert_eq!(error.field(), "authentication.oidc.issuer", "{error}");
        assert!(error.to_string().contains("query"), "{error}");
        assert!(!error.to_string().contains("query-canary"), "{error}");
    }
}

#[test]
fn a_secret_reference_reads_and_writes_as_its_text() {
    let reference: SecretReference =
        serde_json::from_value(serde_json::json!("secret:file/a")).expect("reference parses");
    assert_eq!(
        serde_json::to_value(&reference).unwrap(),
        serde_json::json!("secret:file/a")
    );
    let error = serde_json::from_value::<SecretReference>(serde_json::json!("literal-value"))
        .expect_err("literal refused");
    assert!(!error.to_string().contains("literal-value"), "{error}");
    assert!(!error.to_string().contains('\u{1f}'), "{error:?}");
    assert!(
        error
            .to_string()
            .starts_with("expected an exact secret:env/NAME or secret:file/name reference"),
        "{error}"
    );
    let ordered = std::collections::BTreeSet::from([
        SecretReference::parse("secret:file/b").unwrap(),
        SecretReference::parse("secret:file/a").unwrap(),
    ]);
    assert_eq!(
        ordered
            .iter()
            .map(SecretReference::as_str)
            .collect::<Vec<_>>(),
        ["secret:file/a", "secret:file/b"]
    );
}

fn clients(yaml: &str) -> OidcClientsConfig {
    read_block(yaml).expect("clients parse")
}

#[test]
fn oidc_clients_default_to_no_rule_and_bound_the_assertion_issuer_map() {
    let field = "authentication.oidc";
    let empty = clients("allowedClients: unrestricted");
    assert!(empty.allowed_clients.is_empty());
    assert!(empty.assertion_issuers.is_empty());
    empty.check(field).expect("no rule");
    clients("allowedClients: [portal]\nassertionIssuers: {portal: [https://assert.example.test]}")
        .check(field)
        .expect("one client, one authority");

    let many_clients = (0..=MAX_ASSERTION_ISSUER_CLIENTS)
        .map(|index| format!("c{index}: [https://a.example.test]"))
        .collect::<Vec<_>>()
        .join(", ");
    let many_issuers = (0..=MAX_ASSERTION_ISSUERS_PER_CLIENT)
        .map(|index| format!("https://a{index}.example.test"))
        .collect::<Vec<_>>()
        .join(", ");
    for (reason, yaml) in [
        (
            "too many clients",
            format!("allowedClients: unrestricted\nassertionIssuers: {{{many_clients}}}"),
        ),
        (
            "an empty client",
            "allowedClients: unrestricted\nassertionIssuers: {'': [https://a.example.test]}".to_owned(),
        ),
        (
            "an oversized client",
            format!(
                "allowedClients: unrestricted\nassertionIssuers: {{{}: [https://a.example.test]}}",
                "c".repeat(MAX_ASSERTION_ISSUER_CLIENT_BYTES + 1)
            ),
        ),
        (
            "too many issuers for one client",
            format!("allowedClients: unrestricted\nassertionIssuers: {{portal: [{many_issuers}]}}"),
        ),
        (
            "an empty issuer",
            "allowedClients: unrestricted\nassertionIssuers: {portal: ['']}".to_owned(),
        ),
        (
            "an oversized issuer",
            format!(
                "allowedClients: unrestricted\nassertionIssuers: {{portal: [{}]}}",
                "i".repeat(MAX_ASSERTION_ISSUER_BYTES + 1)
            ),
        ),
        (
            "a repeated issuer",
            "allowedClients: unrestricted\nassertionIssuers: {portal: [https://a.example.test, https://a.example.test]}"
                .to_owned(),
        ),
    ] {
        let error = clients(&yaml).check(field).expect_err(reason);
        assert_eq!(
            error.kind(),
            ConfigBlockErrorKind::InvalidAssertionIssuers,
            "{reason}"
        );
        assert_eq!(error.field(), "authentication.oidc.assertionIssuers");
        assert!(!error.to_string().contains("example.test"), "{reason}");
    }
}

#[test]
fn cfg_empty_2_the_allowed_clients_are_decided_in_every_file() {
    let listed = clients("allowedClients: [portal, kiosk]");
    assert_eq!(listed.allowed_clients, ["portal", "kiosk"]);
    assert_eq!(
        serde_json::to_value(&listed).unwrap(),
        serde_json::json!({"allowedClients": ["portal", "kiosk"]})
    );
    let unrestricted = clients("allowedClients: unrestricted");
    assert!(unrestricted.allowed_clients.is_empty());
    assert_eq!(
        serde_json::to_value(&unrestricted).unwrap(),
        serde_json::json!({"allowedClients": "unrestricted"})
    );

    let omitted = read_block::<OidcClientsConfig>("{}").expect_err("the omission is refused");
    assert_eq!(codes(&omitted), ["config.missing-key"]);
    assert!(
        omitted.diagnostics()[0].message.contains("allowedClients"),
        "{}",
        omitted.diagnostics()[0].message
    );

    for refused in ["allowedClients: []", "allowedClients: portal"] {
        let report = read_block::<OidcClientsConfig>(refused).expect_err(refused);
        assert_eq!(codes(&report), ["config.invalid-value"], "{refused}");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.path, "/allowedClients", "{refused}");
        assert!(
            diagnostic.suggested_action.contains("write unrestricted"),
            "{}",
            diagnostic.suggested_action
        );
        assert!(
            !diagnostic.message.contains("portal"),
            "{}",
            diagnostic.message
        );
    }
}

#[test]
fn cfg_id_6_a_repeated_allowed_client_is_refused_at_the_repeated_item() {
    let report = read_block::<OidcClientsConfig>("allowedClients: [portal, kiosk, portal]")
        .expect_err("a repeated client is refused");
    assert_eq!(codes(&report), ["config.duplicate-item"]);
    assert_eq!(report.diagnostics()[0].path, "/allowedClients/2");
}

#[test]
fn an_empty_assertion_issuer_map_is_refused_and_omission_applies_no_rule() {
    let error = read_block::<OidcClientsConfig>("assertionIssuers: {}")
        .expect_err("an empty map is not how a file says no rule");
    assert!(error.to_string().contains("at least one client"), "{error}");
    let omitted =
        serde_json::to_string(&clients("allowedClients: unrestricted")).expect("serialize");
    assert!(!omitted.contains("assertionIssuers"), "{omitted}");
}

#[test]
fn a_listed_client_with_no_assertion_issuers_is_refused_at_that_client() {
    let report = read_block::<OidcClientsConfig>(
        "allowedClients: unrestricted\nassertionIssuers:\n  portal: [https://assert.example.test]\n  kiosk: []\n",
    )
    .expect_err("an empty issuer list is not how a file says no authority");
    assert_eq!(codes(&report), ["config.invalid-value"]);
    let diagnostic = &report.diagnostics()[0];
    assert_eq!(diagnostic.path, "/assertionIssuers/kiosk");
    assert!(
        diagnostic.message.contains("at least one assertion issuer"),
        "{}",
        diagnostic.message
    );
    assert!(
        diagnostic.suggested_action.contains("remove the client"),
        "{}",
        diagnostic.suggested_action
    );
}

#[test]
fn a_secret_failure_names_the_member_and_never_the_reference() {
    for error in [
        SecretError::InvalidReference,
        SecretError::ProviderDisabled,
        SecretError::InvalidProviderConfiguration,
        SecretError::Unavailable,
        SecretError::UnsafeFile,
        SecretError::Read,
        SecretError::InvalidValue,
    ] {
        let sentence = describe_secret_failure(
            "tokenClient.privateKeyRef",
            "secret:file/reference-canary",
            &error,
        );
        assert!(sentence.contains("tokenClient.privateKeyRef"), "{sentence}");
        assert!(!sentence.contains("reference-canary"), "{sentence}");
    }
}
