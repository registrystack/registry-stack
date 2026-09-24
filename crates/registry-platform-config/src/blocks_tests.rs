use super::*;

fn providers(yaml: &str) -> SecretProvidersConfig {
    serde_norway::from_str(yaml).expect("providers parse")
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
    assert!(serde_norway::from_str::<SecretProvidersConfig>("environment: {x: 1}").is_err());
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
    let database: DatabaseConfig = serde_norway::from_str(
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
fn jwks_source_has_three_kinds_and_defaults_to_discovery() {
    assert_eq!(JwksSource::default(), JwksSource::Discovery);
    let uri: JwksSource =
        serde_norway::from_str("kind: uri\nuri: https://issuer.example.test/jwks").unwrap();
    assert_eq!(uri.uri(), Some("https://issuer.example.test/jwks"));
    uri.check("authentication.oidc.jwksSource", false)
        .expect("https uri");
    let static_source: JwksSource =
        serde_norway::from_str("kind: static\ndocumentRef: secret:file/jwks").unwrap();
    assert_eq!(static_source.document_ref(), Some("secret:file/jwks"));
    assert!(serde_norway::from_str::<JwksSource>("kind: static\nuri: x").is_err());

    for (uri, loopback) in [
        ("http://issuer.example.test/jwks", true),
        ("http://127.0.0.1:1/jwks", false),
        ("https://user:pass@issuer.example.test/jwks", false),
        ("not a url", false),
    ] {
        let source = JwksSource::Uri {
            uri: uri.to_owned(),
        };
        let error = source
            .check("authentication.oidc.jwksSource", loopback)
            .expect_err("refused uri");
        assert_eq!(error.field(), "authentication.oidc.jwksSource.uri");
    }
    JwksSource::Uri {
        uri: "http://127.0.0.1:1/jwks".to_owned(),
    }
    .check("authentication.oidc.jwksSource", true)
    .expect("supervised loopback");
}

#[test]
fn package_root_is_absolute_and_the_pin_is_a_sha256_label() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let package = PackageConfig {
        root: PathBuf::from("/srv/package"),
        expected_digest: Some(digest.clone()),
    };
    package.check().expect("valid package");
    package.verify_digest(Some(&digest)).expect("matches");

    let mismatch = package
        .verify_digest(Some("sha256:other"))
        .expect_err("mismatch");
    assert!(mismatch.to_string().contains("package.expectedDigest"));
    assert!(mismatch
        .to_string()
        .contains("deploy the pinned package or update package.expectedDigest"));
    let missing = package.verify_digest(None).expect_err("no identity");
    assert!(missing.to_string().contains("carries no identity"));

    PackageConfig {
        root: PathBuf::from("/srv/package"),
        expected_digest: None,
    }
    .verify_digest(None)
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
    let listener: ListenerConfig = serde_norway::from_str("bind: \"[::1]:8080\"").unwrap();
    assert_eq!(listener.bind.socket_addr().port(), 8080);
    for bad in ["localhost:8080", "127.0.0.1", "8080"] {
        let error = serde_norway::from_str::<ListenerConfig>(&format!("bind: \"{bad}\""))
            .expect_err("refused bind");
        assert!(error
            .to_string()
            .contains("listener.bind must be host:port"));
    }
    assert!(serde_norway::from_str::<ListenerConfig>("address: 127.0.0.1:1").is_err());
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
