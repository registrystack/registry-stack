// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::destination::{
    DestinationDnsFamily, DestinationSendError, EventDeliveryHeaders,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::event_destination::EventDestinationActivationError;
use registry_server::runtime_config::{
    load_runtime_config, load_runtime_config_with_env, parse_runtime_config,
    parse_runtime_config_with_env, RuntimeConfigError, RUNTIME_CONFIG_API_VERSION,
    RUNTIME_CONFIG_KIND,
};
use serde_json::{json, Value};

const DATABASE_URL_CANARY: &str =
    "postgresql://registry_runtime:database-url-canary@db.example/registry";
const MIGRATION_DATABASE_URL_CANARY: &str =
    "postgresql://registry_migration:migration-database-url-canary@db.example/registry";
const AUDIT_KEY_CANARY: &str = "audit-key-canary-012345678901234567890123456789";
const EXPANDED_CANARY: &str = "runtime-expanded-canary";
const STATIC_JWKS_ENV: &str = "REGISTRY_SERVER_RUNTIME_CONFIG_STATIC_JWKS";

#[test]
fn public_origin_accepts_only_explicit_web_origins_and_redacts_debug() {
    use registry_server::runtime_config::PublicOrigin;
    for (input, expected) in [
        ("https://registry.example/", "https://registry.example"),
        (
            "https://registry.example:8443",
            "https://registry.example:8443",
        ),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://[::1]:8080/", "http://[::1]:8080"),
        ("http://localhost:8080", "http://localhost:8080"),
    ] {
        let origin = PublicOrigin::parse(input).expect("explicit HTTPS or loopback origin");
        assert_eq!(origin.as_str(), expected);
        assert!(!format!("{origin:?}").contains(input));
    }
    for input in [
        "",
        "/relative",
        "//registry.example",
        "ftp://registry.example",
        "http://registry.example",
        "http://127.0.0.1.attacker.example",
        "https://user:secret@registry.example",
        "https://registry.example/path",
        "https://registry.example?token=secret",
        "https://registry.example#fragment",
        "https://registry.example:0",
        "https://registry.example:invalid",
        "https://registry.example:",
        "https://registry.example:65536",
        " https://registry.example",
        "https://registry.example\n",
    ] {
        assert!(
            PublicOrigin::parse(input).is_err(),
            "origin accepted {input:?}"
        );
    }
}

fn valid_runtime(secret_root: &Path, package_root: &Path, trust_anchor: &Path) -> String {
    format!(
        r#"
apiVersion: {api_version}
kind: {kind}
listener:
  bind: 127.0.0.1:8080
identity:
  environment: production
  instanceId: registry-primary
  databaseId: registry-db
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {secret_root}
database:
  runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL
  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {package_root}
  trustAnchorPath: {trust_anchor}
  compilerSourceRevision: source-revision-1
  activeRevision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
        api_version = RUNTIME_CONFIG_API_VERSION,
        kind = RUNTIME_CONFIG_KIND,
        secret_root = secret_root.display(),
        package_root = package_root.display(),
        trust_anchor = trust_anchor.display()
    )
}

fn runtime_with_event_destinations(fixture: &RuntimeFixture, bindings: &str) -> String {
    valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace(
        "eventDestinations: {}\n",
        &format!("eventDestinations:\n{bindings}"),
    )
}

fn event_destination_binding(
    logical_id: &str,
    origin: &str,
    path: &str,
    key_ref: &str,
    timeout_ms: u32,
    maximum_attempts: u8,
) -> String {
    format!(
        r#"  {logical_id}:
    origin: {origin}
    path: {path}
    networkProfile: productionHttps
    dnsFamily: dualStackStrict
    allowedPrivateCidrs: []
    hmacSha256KeyRef: {key_ref}
    classificationCeiling: restricted
    deliveryCeilings:
      attemptTimeoutMilliseconds: {timeout_ms}
      maximumAttempts: {maximum_attempts}
"#
    )
}

fn compiled_webhooks(destinations: &[(&str, u32, u8)]) -> registry_server::CompiledRegistry {
    let events = destinations
        .iter()
        .enumerate()
        .map(
            |(index, (destination_id, _timeout_ms, _maximum_attempts))| {
                let mut event = json!({
                    "id": format!("case-event-{index}"),
                    "trigger": if index == 0 { "created" } else { "patched" },
                    "projection": ["label"],
                    "webhook": {
                        "destinationId": destination_id
                    }
                });
                if index == 0 {
                    event["when"] = json!({
                        "kind": "fields",
                        "afterEquals": {"eligibility": "eligible"}
                    });
                }
                event
            },
        )
        .collect::<Vec<Value>>();
    let project = json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "runtime-event-destinations", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"},
        "entities": [{
            "id": "case",
            "primaryDataset": "test-dataset",
            "route": "cases",
            "mutationMode": "mutable",
            "tombstone": true,
            "classification": "internal",
            "fields": [
                {"id": "label", "type": "string", "maxLength": 64, "classification": "internal"},
                {"id": "eligibility", "type": "string", "maxLength": 32, "classification": "restricted"}
            ],
            "events": events
        }]
    });
    let parsed = parse_project_json(&serde_json::to_vec(&project).expect("project serializes"))
        .expect("project parses");
    compile_project(&parsed, &[], CompileProfile::Authoring).expect("webhooks compile")
}

fn event_headers() -> EventDeliveryHeaders<'static> {
    EventDeliveryHeaders {
        id: b"event-id",
        source: b"urn:registrystack:registry:example:instance:primary",
        event_type: b"case.created",
        time: b"2026-08-30T00:00:00Z",
        dataschema: b"urn:registrystack:registry:example:event:case.created:schema:sha256:aaa",
        generation: b"1",
        attempt: b"1",
        delivery_time: b"2026-08-30T00:00:01Z",
        idempotency_key: b"delivery-key",
        signature: b"v1=signature",
    }
}

#[test]
fn strict_runtime_file_loads_and_constructs_existing_runtime_inputs() {
    let _guard = environment_lock();
    let fixture = RuntimeFixture::new();
    let config_path = fixture.path("runtime.yaml");
    fs::write(
        &config_path,
        valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config writes");
    std::env::set_var(
        "REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL",
        DATABASE_URL_CANARY,
    );
    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL");

    let config = load_runtime_config(&config_path).expect("runtime config loads");

    assert_eq!(config.listener().bind().to_string(), "127.0.0.1:8080");
    assert_eq!(config.identity().environment(), "production");
    assert_eq!(
        config.database().pool_bounds().wait_timeout,
        Duration::from_secs(1)
    );
    assert_eq!(
        config.database().roles().migration().as_str(),
        "registry_migration"
    );
    assert_eq!(config.package().active_sequence(), 1);
    assert_eq!(
        config.event_delivery().payload_retention(),
        Duration::from_secs(7 * 24 * 60 * 60)
    );
    assert_eq!(
        config.package().compiler_source_revision(),
        "source-revision-1"
    );

    let package = config.package_load_context();
    assert_eq!(package.environment, "production");
    assert_eq!(package.database_id, "registry-db");
    assert!(package.trust_anchor.is_some());

    let verifier = config.authentication().oidc().token_verifier_config();
    assert_eq!(verifier.issuer, "https://issuer.example");
    assert_eq!(verifier.audiences, vec!["urn:registry-server:test"]);
    assert_eq!(
        verifier.allowed_algorithms,
        vec![jsonwebtoken::Algorithm::EdDSA]
    );
    assert_eq!(verifier.allowed_clients, vec!["registry-client"]);
    assert!(verifier.denied_kids.contains("denied-kid"));

    let discovery = config.authentication().oidc().discovery_config();
    assert!(discovery.jwks_uri_override.is_none());
    assert_eq!(
        config
            .authentication()
            .oidc()
            .jwks_fetcher_config()
            .request_timeout,
        Duration::from_secs(5)
    );
    let _claims = config.authentication().authority_claim_config();
    let database_result = config.runtime_database_connection_config();
    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL");
    if let Err(error) = database_result {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(DATABASE_URL_CANARY));
    }
    let _audit = config
        .audit_profile()
        .expect("keyed audit profile builds from protected file secret");
    let _cursor = config
        .cursor_codec()
        .expect("cursor codec builds from protected file secret");
}

#[test]
fn runtime_document_identity_is_required_and_exact() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );

    assert_eq!(
        parse_runtime_config_with_env(
            &base.replace(
                RUNTIME_CONFIG_API_VERSION,
                "registry.registrystack.org/server-runtime/v2"
            ),
            env_lookup
        )
        .expect_err("unsupported apiVersion refused"),
        RuntimeConfigError::InvalidApiVersion
    );
    assert_eq!(
        parse_runtime_config_with_env(
            &base.replace(RUNTIME_CONFIG_KIND, "RegistryProject"),
            env_lookup
        )
        .expect_err("unsupported kind refused"),
        RuntimeConfigError::InvalidKind
    );
    assert_eq!(
        parse_runtime_config_with_env(
            &base.replace(&format!("apiVersion: {RUNTIME_CONFIG_API_VERSION}\n"), ""),
            env_lookup
        )
        .expect_err("missing apiVersion refused by strict document shape"),
        RuntimeConfigError::Document
    );
    assert_eq!(
        parse_runtime_config_with_env(
            &base.replace(&format!("kind: {RUNTIME_CONFIG_KIND}\n"), ""),
            env_lookup
        )
        .expect_err("missing kind refused by strict document shape"),
        RuntimeConfigError::Document
    );
}

#[test]
fn operational_defaults_materialize_without_defaulting_authority() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    let raw = base
        .clone()
    .replace(
        "    waitTimeoutMilliseconds: 1000\n    createTimeoutMilliseconds: 1000\n    recycleTimeoutMilliseconds: 1000\n",
        "",
    )
    .replace(
        "    jwksCache:\n      cacheTtlSeconds: 600\n      negativeCacheTtlSeconds: 60\n      refreshCooldownSeconds: 30\n      maxDocumentBytes: 65536\n      requestTimeoutMilliseconds: 5000\n      outageToleranceSeconds: 900\n",
        "",
    )
    .replace("  maxAgeSeconds: 300\n", "")
    .replace(
        "operationalTimeouts:\n  httpRequestMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\n  recordLockMilliseconds: 5000\n  migrationLockMilliseconds: 30000\n  migrationStatementMilliseconds: 60000\n",
        "",
    );

    let config = parse_runtime_config_with_env(&raw, env_lookup)
        .expect("safe operational defaults materialize");

    assert_eq!(config.database().pool_bounds().max_size, 4);
    assert_eq!(
        config.database().pool_bounds().wait_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(
        config.database().pool_bounds().create_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(
        config.database().pool_bounds().recycle_timeout,
        Duration::from_secs(30)
    );
    let jwks = config.authentication().oidc().jwks_fetcher_config();
    assert_eq!(jwks.cache_ttl, Duration::from_secs(600));
    assert_eq!(jwks.negative_cache_ttl, Duration::from_secs(60));
    assert_eq!(jwks.refresh_cooldown, Duration::from_secs(30));
    assert_eq!(jwks.max_doc_bytes, 65_536);
    assert_eq!(jwks.request_timeout, Duration::from_secs(5));
    assert_eq!(jwks.outage_tolerance, Duration::from_secs(900));
    assert_eq!(config.cursor().max_age(), Duration::from_secs(300));
    assert_eq!(
        config.event_delivery().payload_retention(),
        Duration::from_secs(7 * 24 * 60 * 60)
    );
    assert_eq!(
        config.operational_timeouts().http_request,
        Duration::from_secs(10)
    );
    assert_eq!(
        config.operational_timeouts().shutdown_grace,
        Duration::from_secs(30)
    );
    assert_eq!(
        config.operational_timeouts().record_lock,
        Duration::from_secs(5)
    );
    assert_eq!(
        config.operational_timeouts().migration_lock,
        Duration::from_secs(30)
    );
    assert_eq!(
        config.operational_timeouts().migration_statement,
        Duration::from_secs(60)
    );

    let partial_raw = base
        .replace(
            "    jwksCache:\n      cacheTtlSeconds: 600\n      negativeCacheTtlSeconds: 60\n      refreshCooldownSeconds: 30\n      maxDocumentBytes: 65536\n      requestTimeoutMilliseconds: 5000\n      outageToleranceSeconds: 900\n",
            "    jwksCache:\n      requestTimeoutMilliseconds: 5000\n",
        )
        .replace(
            "operationalTimeouts:\n  httpRequestMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\n  recordLockMilliseconds: 5000\n  migrationLockMilliseconds: 30000\n  migrationStatementMilliseconds: 60000\n",
            "operationalTimeouts:\n  httpRequestMilliseconds: 10000\n",
        );
    let partial = parse_runtime_config_with_env(&partial_raw, env_lookup)
        .expect("partial operational sections receive safe field defaults");
    let jwks = partial.authentication().oidc().jwks_fetcher_config();
    assert_eq!(jwks.cache_ttl, Duration::from_secs(600));
    assert_eq!(jwks.negative_cache_ttl, Duration::from_secs(60));
    assert_eq!(jwks.refresh_cooldown, Duration::from_secs(30));
    assert_eq!(jwks.max_doc_bytes, 65_536);
    assert_eq!(jwks.request_timeout, Duration::from_secs(5));
    assert_eq!(jwks.outage_tolerance, Duration::from_secs(900));
    assert_eq!(
        partial.operational_timeouts().http_request,
        Duration::from_secs(10)
    );
    assert_eq!(
        partial.operational_timeouts().shutdown_grace,
        Duration::from_secs(30)
    );
    assert_eq!(
        partial.operational_timeouts().record_lock,
        Duration::from_secs(5)
    );
    assert_eq!(
        partial.operational_timeouts().migration_lock,
        Duration::from_secs(30)
    );
    assert_eq!(
        partial.operational_timeouts().migration_statement,
        Duration::from_secs(60)
    );

    for required_authority in [
        ("identity:\n", RuntimeConfigError::Document),
        ("secretProviders:\n", RuntimeConfigError::Document),
        ("database:\n", RuntimeConfigError::Document),
        ("package:\n", RuntimeConfigError::Document),
        ("authentication:\n", RuntimeConfigError::Document),
        ("audit:\n", RuntimeConfigError::Document),
        ("cursor:\n", RuntimeConfigError::Document),
        (
            "  runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n",
            RuntimeConfigError::Document,
        ),
        ("  roles:\n", RuntimeConfigError::Document),
        (
            "    issuer: https://issuer.example\n",
            RuntimeConfigError::Document,
        ),
        (
            "  hashKeyRef: secret:file/audit-key\n",
            RuntimeConfigError::Document,
        ),
        (
            "  secretRef: secret:file/cursor-key\n",
            RuntimeConfigError::Document,
        ),
    ] {
        let (line, expected) = required_authority;
        assert_eq!(
            parse_runtime_config_with_env(&raw.replace(line, ""), env_lookup)
                .expect_err("authority-bearing runtime member is never defaulted"),
            expected
        );
    }
}

#[test]
fn runtime_config_errors_expose_stable_value_free_metadata() {
    let cases = [
        (
            RuntimeConfigError::InvalidApiVersion,
            "runtime_config.invalid_api_version",
            "/apiVersion",
        ),
        (
            RuntimeConfigError::InvalidKind,
            "runtime_config.invalid_kind",
            "/kind",
        ),
        (
            RuntimeConfigError::InvalidDatabase,
            "runtime_config.invalid_database",
            "/database",
        ),
        (
            RuntimeConfigError::InvalidOidc,
            "runtime_config.invalid_oidc",
            "/authentication/oidc",
        ),
        (
            RuntimeConfigError::InvalidEventDestination,
            "runtime_config.invalid_event_destination",
            "/eventDestinations",
        ),
        (RuntimeConfigError::Secret, "runtime_config.secret", "/"),
        (
            RuntimeConfigError::PackageRootUnavailable,
            "runtime_config.package_root_unavailable",
            "/package/root",
        ),
        (
            RuntimeConfigError::UnsafePackageRoot,
            "runtime_config.unsafe_package_root",
            "/package/root",
        ),
        (
            RuntimeConfigError::TrustAnchorUnavailable,
            "runtime_config.trust_anchor_unavailable",
            "/package/trustAnchorPath",
        ),
        (
            RuntimeConfigError::UnsafeTrustAnchor,
            "runtime_config.unsafe_trust_anchor",
            "/package/trustAnchorPath",
        ),
        (
            RuntimeConfigError::SecretProviderRootUnavailable,
            "runtime_config.secret_provider_root_unavailable",
            "/secretProviders/file/root",
        ),
        (
            RuntimeConfigError::UnsafeSecretProviderRoot,
            "runtime_config.unsafe_secret_provider_root",
            "/secretProviders/file/root",
        ),
        (
            RuntimeConfigError::InvalidOidcLeeway,
            "runtime_config.invalid_oidc_leeway",
            "/authentication/oidc/leewayMilliseconds",
        ),
    ];

    for (error, code, path) in cases {
        let metadata = error.metadata();
        assert_eq!(error.code(), code);
        assert_eq!(error.path(), path);
        assert_eq!(metadata.code(), code);
        assert_eq!(metadata.path(), path);
        let rendered = format!("{error:?} {error} {metadata:?}");
        for canary in [
            DATABASE_URL_CANARY,
            MIGRATION_DATABASE_URL_CANARY,
            AUDIT_KEY_CANARY,
            "REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL",
            "registry_runtime",
            "https://issuer.example",
        ] {
            assert!(!rendered.contains(canary), "{code} leaked {canary}");
        }
    }
}

#[test]
fn webhook_payload_retention_is_deployment_selected_and_capped_at_thirty_days() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    for days in [1_u8, 30_u8] {
        let config = parse_runtime_config(&format!(
            "{base}\neventDelivery:\n  payloadRetentionDays: {days}\n"
        ))
        .expect("bounded deployment retention parses");
        assert_eq!(
            config.event_delivery().payload_retention(),
            Duration::from_secs(u64::from(days) * 24 * 60 * 60)
        );
    }
    for days in [0_u8, 31_u8] {
        assert_eq!(
            parse_runtime_config(&format!(
                "{base}\neventDelivery:\n  payloadRetentionDays: {days}\n"
            ))
            .err(),
            Some(RuntimeConfigError::InvalidBounds)
        );
    }
}

#[test]
fn local_runtime_does_not_require_or_supply_package_trust_authority() {
    let fixture = RuntimeFixture::new();
    let missing_anchor = fixture.path("unused-local-trust-anchor.json");
    let config_path = fixture.path("runtime-local.yaml");
    let raw = valid_runtime(&fixture.secret_root, &fixture.package_root, &missing_anchor)
        .replace("environment: production", "environment: local")
        .replace(
            "databaseInitializationEnvironment: production",
            "databaseInitializationEnvironment: local",
        );
    fs::write(&config_path, raw).expect("local runtime config writes");

    let config = load_runtime_config(&config_path)
        .expect("local runtime does not require a production trust anchor file");
    assert!(config.package_trust_anchor().is_none());
    assert!(config.package_load_context().trust_anchor.is_none());
}

#[test]
fn governed_unknown_keys_are_refused_before_they_become_runtime() {
    let fixture = RuntimeFixture::new();
    let mut raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    raw.push_str("entities: []\n");
    assert_eq!(
        parse_runtime_config_with_env(&raw, env_lookup).expect_err("governed key refused"),
        RuntimeConfigError::GovernedMember
    );
}

#[test]
fn metrics_listener_is_absent_by_default_and_optional() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    let config = parse_runtime_config_with_env(&base, env_lookup).expect("baseline runtime parses");
    assert!(
        config.metrics_listener().is_none(),
        "no metrics surface exists unless the operator names one"
    );

    let configured = format!("{base}metricsListener:\n  bind: 127.0.0.1:9100\n");
    let config =
        parse_runtime_config_with_env(&configured, env_lookup).expect("private metrics listener");
    let listener = config.metrics_listener().expect("listener is configured");
    assert_eq!(listener.bind(), "127.0.0.1:9100".parse().unwrap());
    assert!(
        !format!("{listener:?}").contains("9100"),
        "bind stays redacted"
    );
}

#[test]
fn metrics_listener_refuses_public_unspecified_and_ephemeral_bindings() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    for bind in [
        "0.0.0.0:9100",
        "8.8.8.8:9100",
        "\"[::]:9100\"",
        "127.0.0.1:0",
        "localhost:9100",
        "127.0.0.1",
    ] {
        let configured = format!("{base}metricsListener:\n  bind: {bind}\n");
        let error = parse_runtime_config_with_env(&configured, env_lookup)
            .expect_err("non-private metrics binding is refused");
        assert_eq!(
            error,
            RuntimeConfigError::InvalidMetricsListener,
            "binding {bind} refused"
        );
        assert_eq!(error.metadata().path(), "/metricsListener");
        assert_eq!(
            error.metadata().code(),
            "runtime_config.invalid_metrics_listener"
        );
    }
}

#[test]
fn metrics_listener_refuses_shared_registry_binding() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    // Same address as the Registry listener itself, and the dual-stack
    // wildcard equivalent of it.
    for bind in ["127.0.0.1:8080", "\"[::]:8080\""] {
        let configured = format!("{base}metricsListener:\n  bind: {bind}\n");
        assert_eq!(
            parse_runtime_config_with_env(&configured, env_lookup)
                .expect_err("shared binding is refused"),
            RuntimeConfigError::InvalidMetricsListener
        );
    }
    // An IPv6 wildcard Registry listener also covers the IPv4 metrics port
    // on hosts that create dual-stack sockets.
    let wildcard = base.replace("bind: 127.0.0.1:8080", "bind: \"[::]:8080\"");
    let configured = format!("{wildcard}metricsListener:\n  bind: 127.0.0.1:8080\n");
    assert_eq!(
        parse_runtime_config_with_env(&configured, env_lookup)
            .expect_err("dual-stack overlap is refused"),
        RuntimeConfigError::InvalidMetricsListener
    );
}

#[test]
fn metrics_listener_refuses_unknown_members() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    let configured = format!("{base}metricsListener:\n  bind: 127.0.0.1:9100\n  labels: none\n");
    assert_eq!(
        parse_runtime_config_with_env(&configured, env_lookup)
            .expect_err("unknown metrics member is refused"),
        RuntimeConfigError::Document
    );
}

#[test]
fn raw_database_urls_inline_secrets_and_plaintext_posture_are_refused() {
    let fixture = RuntimeFixture::new();
    for replacement in [
        format!(
            "runtimeUrlRef: {}\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n  pool:",
            "postgresql://registry_runtime:raw-secret@db.example/registry"
        ),
        "runtimeUrlRef: secret:env/lowercase\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n  pool:".to_owned(),
        "runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n  plaintext: true\n  pool:".to_owned(),
        "runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n  password: inline-secret\n  pool:".to_owned(),
    ] {
        let raw = valid_runtime(&fixture.secret_root, &fixture.package_root, &fixture.trust_anchor)
            .replace(
                "runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n  pool:",
                &replacement,
            );
        assert_eq!(
            parse_runtime_config_with_env(&raw, env_lookup)
                .expect_err("unsafe database material refused"),
            RuntimeConfigError::InvalidDatabase
        );
    }
}

#[test]
fn old_single_database_url_ref_is_refused_by_strict_schema() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(&fixture.secret_root, &fixture.package_root, &fixture.trust_anchor)
        .replace(
            "runtimeUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n  migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL\n",
            "urlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL\n",
        );

    assert_eq!(
        parse_runtime_config_with_env(&raw, env_lookup)
            .expect_err("legacy single database URL ref is refused"),
        RuntimeConfigError::Document
    );
}

#[test]
fn database_role_specific_resolvers_refuse_wrong_role_without_leaking_values() {
    let _guard = environment_lock();
    let fixture = RuntimeFixture::new();
    let config = parse_runtime_config_with_env(
        &valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
        env_lookup,
    )
    .expect("runtime parses");

    std::env::set_var(
        "REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL",
        MIGRATION_DATABASE_URL_CANARY,
    );
    let runtime_error = config
        .runtime_database_connection_config()
        .expect_err("migration URL cannot satisfy runtime connection");
    assert_eq!(runtime_error, RuntimeConfigError::InvalidDatabase);
    let rendered = format!("{runtime_error:?} {runtime_error}");
    assert!(!rendered.contains(MIGRATION_DATABASE_URL_CANARY));
    assert!(!rendered.contains("registry_migration"));

    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL");
    std::env::set_var(
        "REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL",
        DATABASE_URL_CANARY,
    );
    let migration_error = config
        .migration_database_connection_config()
        .expect_err("runtime URL cannot satisfy migration connection");
    assert_eq!(migration_error, RuntimeConfigError::InvalidDatabase);
    let rendered = format!("{migration_error:?} {migration_error}");
    assert!(!rendered.contains(DATABASE_URL_CANARY));
    assert!(!rendered.contains("registry_runtime"));
    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL");
}

#[test]
fn migration_database_resolver_uses_only_the_migration_reference() {
    let _guard = environment_lock();
    let fixture = RuntimeFixture::new();
    let config = parse_runtime_config_with_env(
        &valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
        env_lookup,
    )
    .expect("runtime parses");

    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL");
    std::env::set_var(
        "REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL",
        MIGRATION_DATABASE_URL_CANARY,
    );
    let migration_result = config.migration_database_connection_config();
    std::env::remove_var("REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL");
    if let Err(error) = migration_result {
        let rendered = format!("{error:?} {error}");
        assert_ne!(error, RuntimeConfigError::Secret);
        assert!(!rendered.contains(MIGRATION_DATABASE_URL_CANARY));
    }
}

#[test]
fn database_references_must_be_structurally_distinct() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace(
        "migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL",
        "migrationUrlRef: secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL",
    );

    let error = parse_runtime_config_with_env(&raw, env_lookup)
        .expect_err("same database reference is refused");
    assert_eq!(error, RuntimeConfigError::InvalidDatabase);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL"));
}

#[test]
fn invalid_bounds_roles_paths_and_oidc_inputs_are_refused() {
    let fixture = RuntimeFixture::new();
    for (raw, expected) in [
        (
            valid_runtime(
                &fixture.secret_root,
                &fixture.package_root,
                &fixture.trust_anchor,
            )
            .replace("maxSize: 4", "maxSize: 129"),
            RuntimeConfigError::InvalidBounds,
        ),
        (
            valid_runtime(
                &fixture.secret_root,
                &fixture.package_root,
                &fixture.trust_anchor,
            )
            .replace(
                "migration: registry_migration",
                "migration: RegistryMigration",
            ),
            RuntimeConfigError::InvalidDatabase,
        ),
        (
            valid_runtime(
                &fixture.secret_root,
                &fixture.package_root,
                &fixture.trust_anchor,
            )
            .replace("runtime: registry_runtime", "runtime: registry_migration"),
            RuntimeConfigError::InvalidDatabase,
        ),
        (
            valid_runtime(
                &fixture.secret_root,
                &fixture.package_root,
                &fixture.trust_anchor,
            )
            .replace(
                &fixture.package_root.display().to_string(),
                "relative/package",
            ),
            RuntimeConfigError::InvalidPackage,
        ),
        (
            valid_runtime(
                &fixture.secret_root,
                &fixture.package_root,
                &fixture.trust_anchor,
            )
            .replace("principal: registry_principal", "principal: sub"),
            RuntimeConfigError::InvalidOidc,
        ),
    ] {
        assert_eq!(
            parse_runtime_config_with_env(&raw, env_lookup).expect_err("invalid runtime refused"),
            expected
        );
    }
}

#[test]
fn authored_jwks_uri_override_is_refused() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace(
        "    audience: urn:registry-server:test\n",
        "    audience: urn:registry-server:test\n    jwksUri: https://attacker.example/jwks.json\n",
    );
    assert_eq!(
        parse_runtime_config_with_env(&raw, env_lookup).expect_err("JWKS override refused"),
        RuntimeConfigError::Document
    );
}

#[test]
fn jwks_source_is_a_strict_tagged_oidc_member() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    parse_runtime_config_with_env(&raw, env_lookup).expect("omitted source keeps discovery");
    parse_runtime_config_with_env(&runtime_with_discovery_source(&fixture), env_lookup)
        .expect("explicit discovery source parses");
    parse_runtime_config_with_env(
        &runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks"),
        env_lookup,
    )
    .expect("static file source parses without resolving the secret");
    parse_runtime_config_with_env(
        &runtime_with_static_jwks_ref(&fixture, "secret:env/REGISTRY_SERVER_RUNTIME_CONFIG_JWKS"),
        env_lookup,
    )
    .expect("static env source parses without resolving the secret");

    for raw in [
        runtime_with_discovery_source(&fixture).replace(
            "      kind: discovery\n",
            "      kind: discovery\n      documentRef: secret:file/oidc-jwks\n",
        ),
        runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks")
            .replace("      documentRef:", "      keys: []\n      documentRef:"),
        runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks")
            .replace("secret:file/oidc-jwks", "/direct/path/jwks.json"),
        runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks")
            .replace("secret:file/oidc-jwks", "secret:file/../jwks"),
        runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks")
            .replace("kind: static", "kind: remote"),
    ] {
        assert!(
            parse_runtime_config_with_env(&raw, env_lookup).is_err(),
            "invalid JWKS source shape refused"
        );
    }
}

#[tokio::test]
async fn static_jwks_file_and_env_refs_build_a_ready_key_source() {
    let fixture = RuntimeFixture::new();
    let kid = "static-ed25519";
    let jwks = static_jwks_document(&[static_ed25519_jwk(kid)]);
    fixture.write_secret("oidc-jwks", jwks.as_bytes());
    let file_config = parse_runtime_config_with_env(
        &runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks"),
        env_lookup,
    )
    .expect("file-pinned runtime parses");
    let file_source = file_config
        .oidc_key_source()
        .await
        .expect("file-pinned static JWKS constructs");
    file_source
        .ensure_key_set()
        .await
        .expect("static file key set is ready");
    file_source
        .key_for_kid(kid)
        .await
        .expect("static file key is selectable by kid");

    let _guard = async_environment_lock().await;
    std::env::set_var(STATIC_JWKS_ENV, &jwks);
    let env_config = parse_runtime_config_with_env(
        &runtime_with_static_jwks_ref(&fixture, &format!("secret:env/{STATIC_JWKS_ENV}")),
        env_lookup,
    )
    .expect("env-pinned runtime parses");
    let env_source = env_config
        .oidc_key_source()
        .await
        .expect("env-pinned static JWKS constructs");
    std::env::remove_var(STATIC_JWKS_ENV);
    env_source
        .ensure_key_set()
        .await
        .expect("resolved env key set remains ready");
    env_source
        .key_for_kid(kid)
        .await
        .expect("resolved env key is selectable by kid");
}

#[tokio::test]
async fn static_jwks_validation_refuses_unsafe_documents_value_free() {
    let fixture = RuntimeFixture::new();
    let denied = "denied-kid";
    let valid = static_ed25519_jwk("static-ed25519");
    let duplicate = static_jwks_document(&[
        static_ed25519_jwk("static-ed25519"),
        static_ed25519_jwk("static-ed25519"),
    ]);
    let too_many = {
        let keys = (0..=128)
            .map(|index| static_ed25519_jwk(&format!("static-ed25519-{index}")))
            .collect::<Vec<_>>();
        static_jwks_document(&keys)
    };
    let cases = [
        ("top-level-missing", "{}".to_owned(), "EdDSA"),
        (
            "top-level-unknown",
            serde_json::to_string(&json!({"keys":[valid.clone()],"issuer":"issuer-canary"}))
                .expect("JWKS serializes"),
            "EdDSA",
        ),
        ("empty-keys", r#"{"keys":[]}"#.to_owned(), "EdDSA"),
        (
            "keys-not-array",
            r#"{"keys":{"kty":"OKP"}}"#.to_owned(),
            "EdDSA",
        ),
        (
            "private-member",
            static_jwks_document(&[with_member(valid.clone(), "d", json!("private-canary"))]),
            "EdDSA",
        ),
        (
            "unknown-member",
            static_jwks_document(&[with_member(valid.clone(), "x5c", json!(["cert-canary"]))]),
            "EdDSA",
        ),
        (
            "duplicate-json-field",
            format!(
                r#"{{"keys":[{{"kty":"OKP","kid":"duplicate-canary","kid":"duplicate-canary-2","alg":"EdDSA","crv":"Ed25519","x":"{}"}}]}}"#,
                valid["x"].as_str().expect("x is present")
            ),
            "EdDSA",
        ),
        (
            "oct-key",
            r#"{"keys":[{"kty":"oct","kid":"oct-canary","alg":"EdDSA","k":"AA"}]}"#.to_owned(),
            "EdDSA",
        ),
        (
            "missing-kid",
            static_jwks_document(&[without_member(valid.clone(), "kid")]),
            "EdDSA",
        ),
        ("duplicate-kid", duplicate, "EdDSA"),
        (
            "denied-kid",
            static_jwks_document(&[static_ed25519_jwk(denied)]),
            "EdDSA",
        ),
        (
            "empty-kid",
            static_jwks_document(&[with_member(valid.clone(), "kid", json!(""))]),
            "EdDSA",
        ),
        (
            "oversized-kid",
            static_jwks_document(&[with_member(valid.clone(), "kid", json!("k".repeat(513)))]),
            "EdDSA",
        ),
        ("too-many-keys", too_many, "EdDSA"),
        (
            "wrong-alg",
            static_jwks_document(&[with_member(valid.clone(), "alg", json!("ES256"))]),
            "EdDSA",
        ),
        (
            "wrong-type",
            static_jwks_document(&[with_member(valid.clone(), "kty", json!("EC"))]),
            "EdDSA",
        ),
        (
            "wrong-curve",
            static_jwks_document(&[with_member(valid.clone(), "crv", json!("P-256"))]),
            "EdDSA",
        ),
        (
            "bad-use",
            static_jwks_document(&[with_member(valid.clone(), "use", json!("enc"))]),
            "EdDSA",
        ),
        (
            "bad-key-ops",
            static_jwks_document(&[with_member(
                valid.clone(),
                "key_ops",
                json!(["verify", "verify"]),
            )]),
            "EdDSA",
        ),
        (
            "bad-base64",
            static_jwks_document(&[with_member(valid.clone(), "x", json!("not base64"))]),
            "EdDSA",
        ),
        (
            "bad-point",
            static_jwks_document(&[es256_jwk_with_point(
                "bad-point-canary",
                vec![0; 32],
                vec![0; 32],
            )]),
            "ES256",
        ),
        (
            "wrong-ec-curve",
            static_jwks_document(&[with_member(
                es256_jwk_with_point("wrong-curve-canary", vec![1; 32], vec![2; 32]),
                "crv",
                json!("P-384"),
            )]),
            "ES256",
        ),
        (
            "weak-rsa",
            static_jwks_document(&[rsa_jwk("weak-rsa-canary", 255, "AQAB")]),
            "RS256",
        ),
        (
            "oversized-rsa",
            static_jwks_document(&[rsa_jwk("oversized-rsa-canary", 1025, "AQAB")]),
            "RS256",
        ),
        (
            "bad-exponent",
            static_jwks_document(&[rsa_jwk("bad-exponent-canary", 256, "Ag")]),
            "RS256",
        ),
    ];

    for (name, jwks, algorithm) in cases {
        fixture.write_secret("oidc-jwks", jwks.as_bytes());
        let raw = runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks").replace(
            "allowedAlgorithm: EdDSA",
            &format!("allowedAlgorithm: {algorithm}"),
        );
        let config = parse_runtime_config_with_env(&raw, env_lookup).expect("runtime shell parses");
        let error = config
            .oidc_key_source()
            .await
            .expect_err("invalid static JWKS refused");
        assert_eq!(error, RuntimeConfigError::InvalidOidc, "{name}");
        let rendered = format!("{error:?} {error} {config:?}");
        for canary in [
            "oidc-jwks",
            "issuer-canary",
            "private-canary",
            "cert-canary",
            "duplicate-canary",
            "oct-canary",
            "bad-point-canary",
            "wrong-curve-canary",
            "weak-rsa-canary",
            "oversized-rsa-canary",
            "bad-exponent-canary",
        ] {
            assert!(!rendered.contains(canary), "{name} leaked {canary}");
        }
    }
}

#[tokio::test]
async fn static_jwks_resolves_once_and_rotates_only_on_reconstruction() {
    let fixture = RuntimeFixture::new();
    let first_kid = "static-ed25519-first";
    let second_kid = "static-ed25519-second";
    fixture.write_secret(
        "oidc-jwks",
        static_jwks_document(&[static_ed25519_jwk(first_kid)]).as_bytes(),
    );
    let config = parse_runtime_config_with_env(
        &runtime_with_static_jwks_ref(&fixture, "secret:file/oidc-jwks"),
        env_lookup,
    )
    .expect("static runtime parses");
    let first_source = config
        .oidc_key_source()
        .await
        .expect("first static source constructs");
    first_source
        .ensure_key_set()
        .await
        .expect("first source is ready");
    fixture.write_secret(
        "oidc-jwks",
        static_jwks_document(&[static_ed25519_jwk(second_kid)]).as_bytes(),
    );

    first_source
        .key_for_kid(first_kid)
        .await
        .expect("already constructed source keeps the original key");
    assert!(
        first_source.key_for_kid(second_kid).await.is_err(),
        "already constructed source does not reload the rotated file"
    );
    let second_source = config
        .oidc_key_source()
        .await
        .expect("reconstructed source reads the rotated document");
    second_source
        .ensure_key_set()
        .await
        .expect("second source is ready");
    second_source
        .key_for_kid(second_kid)
        .await
        .expect("reconstructed source sees the rotated key");
    assert!(
        second_source.key_for_kid(first_kid).await.is_err(),
        "reconstructed source does not retain stale keys"
    );
}

#[test]
fn debug_and_errors_do_not_render_secret_or_expanded_canaries() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace("production", "${ENVIRONMENT_CANARY}");
    let config = parse_runtime_config_with_env(&raw, |name| match name {
        "ENVIRONMENT_CANARY" => Some(EXPANDED_CANARY.to_owned()),
        _ => env_lookup(name),
    })
    .expect("runtime config with env expansion parses");

    let debug = format!("{config:?}");
    for canary in [
        EXPANDED_CANARY,
        DATABASE_URL_CANARY,
        MIGRATION_DATABASE_URL_CANARY,
        AUDIT_KEY_CANARY,
        "REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL",
        "REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL",
        "audit-key",
    ] {
        assert!(!debug.contains(canary), "debug leaked {canary}");
    }

    let unsafe_raw = raw.replace("registry_purpose", "purpose canary\nextra: true");
    let error = parse_runtime_config_with_env(&unsafe_raw, |name| match name {
        "ENVIRONMENT_CANARY" => Some(EXPANDED_CANARY.to_owned()),
        _ => env_lookup(name),
    })
    .expect_err("invalid document refused");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(EXPANDED_CANARY));
    assert!(!rendered.contains("purpose canary"));
}

#[test]
fn unsafe_embedded_env_expansion_is_refused_without_echoing_value() {
    let fixture = RuntimeFixture::new();
    let raw = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace("https://issuer.example", "https://${OIDC_HOST}");
    let error = parse_runtime_config_with_env(&raw, |name| match name {
        "OIDC_HOST" => Some("issuer.example\nentities: []".to_owned()),
        _ => env_lookup(name),
    })
    .expect_err("unsafe embedded expansion refused");
    assert_eq!(error, RuntimeConfigError::EnvExpansion);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("issuer.example"));
    assert!(!rendered.contains("entities"));
}

#[test]
fn expanded_runtime_document_is_bounded_before_yaml_parsing() {
    let raw = "listener: ${OVERSIZED_RUNTIME_VALUE}\n: malformed\n";
    let error = parse_runtime_config_with_env(raw, |name| match name {
        "OVERSIZED_RUNTIME_VALUE" => Some("runtime-bound-canary".repeat(4096)),
        _ => env_lookup(name),
    })
    .expect_err("oversized expansion refused before parsing");

    assert_eq!(error, RuntimeConfigError::Bounds);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("runtime-bound-canary"));
}

#[cfg(unix)]
#[test]
fn runtime_config_file_must_not_be_a_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = RuntimeFixture::new();
    let target = fixture.path("runtime-target.yaml");
    fs::write(
        &target,
        valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config target writes");
    let link = fixture.path("runtime-link.yaml");
    symlink(&target, &link).expect("runtime config symlink creates");

    assert_eq!(
        load_runtime_config_with_env(&link, env_lookup).expect_err("symlinked runtime refused"),
        RuntimeConfigError::UnsafeFile
    );
}

#[cfg(unix)]
#[test]
fn runtime_config_path_components_must_not_be_symlinks() {
    use std::os::unix::fs::symlink;

    let fixture = RuntimeFixture::new();
    let real_dir = fixture.path("real-config-dir");
    fs::create_dir(&real_dir).expect("real config dir creates");
    let config_path = real_dir.join("runtime.yaml");
    fs::write(
        &config_path,
        valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config writes");
    let linked_dir = fixture.path("linked-config-dir");
    symlink(&real_dir, &linked_dir).expect("runtime config ancestor symlink creates");
    let linked_config = linked_dir.join("runtime.yaml");

    assert_eq!(
        load_runtime_config_with_env(&linked_config, env_lookup)
            .expect_err("symlinked runtime ancestor refused"),
        RuntimeConfigError::UnsafeFile
    );
}

#[cfg(unix)]
#[test]
fn loaded_paths_must_not_be_symlinks() {
    use std::os::unix::fs::symlink;

    let fixture = RuntimeFixture::new();
    let linked_root = fixture.path("linked-package");
    symlink(&fixture.package_root, &linked_root).expect("package symlink creates");
    let raw = valid_runtime(&fixture.secret_root, &linked_root, &fixture.trust_anchor);
    let config_path = fixture.path("runtime-symlink.yaml");
    fs::write(&config_path, raw).expect("runtime config writes");

    assert_eq!(
        load_runtime_config(&config_path).expect_err("symlink path refused"),
        RuntimeConfigError::UnsafePackageRoot
    );

    let linked_anchor = fixture.path("linked-trust-anchor.json");
    symlink(&fixture.trust_anchor, &linked_anchor).expect("trust anchor symlink creates");
    let raw = valid_runtime(&fixture.secret_root, &fixture.package_root, &linked_anchor);
    let anchor_config_path = fixture.path("runtime-anchor-symlink.yaml");
    fs::write(&anchor_config_path, raw).expect("runtime config writes");

    assert_eq!(
        load_runtime_config(&anchor_config_path).expect_err("symlinked trust anchor refused"),
        RuntimeConfigError::UnsafeTrustAnchor
    );

    let linked_secret_root = fixture.path("linked-secrets");
    symlink(&fixture.secret_root, &linked_secret_root).expect("secret root symlink creates");
    let raw = valid_runtime(
        &linked_secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    let secret_config_path = fixture.path("runtime-secret-symlink.yaml");
    fs::write(&secret_config_path, raw).expect("runtime config writes");

    assert_eq!(
        load_runtime_config(&secret_config_path)
            .expect_err("symlinked secret provider root refused"),
        RuntimeConfigError::UnsafeSecretProviderRoot
    );
}

/// A mistyped `--runtime-config` path must read as a missing file, never as a
/// security refusal that accuses the operator of an unsafe deployment.
#[test]
fn a_missing_runtime_config_file_is_unavailable_rather_than_unsafe() {
    let fixture = RuntimeFixture::new();
    for missing in [
        fixture.path("runtme.yaml"),
        fixture.path("absent-directory").join("runtime.yaml"),
    ] {
        let error = load_runtime_config_with_env(&missing, env_lookup)
            .expect_err("a missing runtime configuration file is refused");
        assert_eq!(
            error,
            RuntimeConfigError::Unavailable,
            "{}",
            missing.display()
        );
        assert_eq!(error.code(), "runtime_config.unavailable");
    }
}

/// An unreadable parent directory is a permissions fault, not a symlink attack.
#[cfg(unix)]
#[test]
fn an_unreadable_runtime_config_directory_is_unavailable_rather_than_unsafe() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = RuntimeFixture::new();
    let closed = fixture.path("closed-config-directory");
    fs::create_dir(&closed).expect("closed config directory creates");
    let config_path = closed.join("runtime.yaml");
    fs::write(
        &config_path,
        valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config writes");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000))
        .expect("config directory permissions close");
    let privileged = fs::read_dir(&closed).is_ok();
    let result = load_runtime_config_with_env(&config_path, env_lookup);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700))
        .expect("config directory permissions restore");

    if privileged {
        // A privileged process is not denied by the mode bits, so the refusal
        // this test describes cannot be observed here.
        return;
    }
    assert_eq!(
        result.expect_err("an unreadable runtime configuration directory is refused"),
        RuntimeConfigError::Unavailable
    );
}

/// The package root and the package trust anchor are two separate files, so a
/// missing one must not be reported as the other.
#[test]
fn missing_package_root_and_trust_anchor_are_reported_at_their_own_paths() {
    let fixture = RuntimeFixture::new();
    let missing_root_path = fixture.path("runtime-missing-package-root.yaml");
    fs::write(
        &missing_root_path,
        valid_runtime(
            &fixture.secret_root,
            &fixture.path("absent-package"),
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config writes");
    let missing_anchor_path = fixture.path("runtime-missing-trust-anchor.yaml");
    fs::write(
        &missing_anchor_path,
        valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.path("absent-trust-anchor.json"),
        ),
    )
    .expect("runtime config writes");
    let missing_secret_root_path = fixture.path("runtime-missing-secret-root.yaml");
    fs::write(
        &missing_secret_root_path,
        valid_runtime(
            &fixture.path("absent-secrets"),
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
    )
    .expect("runtime config writes");

    let root_error =
        load_runtime_config(&missing_root_path).expect_err("a missing package root is refused");
    let anchor_error = load_runtime_config(&missing_anchor_path)
        .expect_err("a missing package trust anchor is refused");
    let secret_error = load_runtime_config(&missing_secret_root_path)
        .expect_err("a missing file secret provider root is refused");

    assert_eq!(root_error, RuntimeConfigError::PackageRootUnavailable);
    assert_eq!(root_error.path(), "/package/root");
    assert_eq!(root_error.code(), "runtime_config.package_root_unavailable");
    assert_eq!(anchor_error, RuntimeConfigError::TrustAnchorUnavailable);
    assert_eq!(anchor_error.path(), "/package/trustAnchorPath");
    assert_eq!(
        anchor_error.code(),
        "runtime_config.trust_anchor_unavailable"
    );
    assert!(
        anchor_error.to_string().contains("trust anchor"),
        "the trust anchor refusal names the file it read: {anchor_error}"
    );
    assert_eq!(
        secret_error,
        RuntimeConfigError::SecretProviderRootUnavailable
    );
    assert_eq!(secret_error.path(), "/secretProviders/file/root");
}

/// The verifier applies leeway in whole seconds, so a sub-second value would be
/// silently truncated. Refuse it at load time instead.
#[test]
fn oidc_leeway_must_be_whole_seconds_within_its_documented_range() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    );
    for accepted in [0_u64, 1_000, 60_000, 300_000] {
        let config = parse_runtime_config_with_env(
            &base.replace(
                "leewayMilliseconds: 60000",
                &format!("leewayMilliseconds: {accepted}"),
            ),
            env_lookup,
        )
        .expect("a whole-second leeway is accepted");
        assert_eq!(
            config
                .authentication()
                .oidc()
                .token_verifier_config()
                .leeway,
            Duration::from_millis(accepted)
        );
    }
    for refused in [1_u64, 500, 999, 1_500, 300_001] {
        let error = parse_runtime_config_with_env(
            &base.replace(
                "leewayMilliseconds: 60000",
                &format!("leewayMilliseconds: {refused}"),
            ),
            env_lookup,
        )
        .expect_err("a leeway the verifier cannot apply exactly is refused");
        assert_eq!(error, RuntimeConfigError::InvalidOidcLeeway, "{refused}");
        assert_eq!(error.path(), "/authentication/oidc/leewayMilliseconds");
        assert_eq!(error.code(), "runtime_config.invalid_oidc_leeway");
        let message = error.to_string();
        assert!(
            message.contains("whole number of seconds") && message.contains("300000"),
            "the leeway refusal states the accepted range: {message}"
        );
    }
}

/// `listener.trustedProxy` was removed: nothing in the runtime reads a
/// trusted-proxy posture. `RawListenerConfig` denies unknown fields, so a
/// runtime configuration that still carries `listener.trustedProxy: direct`
/// is refused rather than silently accepted.
#[test]
fn listener_trusted_proxy_is_refused_as_an_unknown_field() {
    let fixture = RuntimeFixture::new();
    let base = valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace("  trustedProxy: direct\n", "");
    let with_trusted_proxy = base.replace(
        "listener:\n  bind: 127.0.0.1:8080\n",
        "listener:\n  bind: 127.0.0.1:8080\n  trustedProxy: direct\n",
    );

    assert_eq!(
        parse_runtime_config_with_env(&with_trusted_proxy, env_lookup)
            .expect_err("listener.trustedProxy is refused as an unknown field"),
        RuntimeConfigError::Document
    );
}

#[test]
fn event_destination_shape_is_strict_and_governed_webhooks_remain_refused() {
    let fixture = RuntimeFixture::new();
    let binding = event_destination_binding(
        "case-operations",
        "https://events.example/",
        "/hooks/registry",
        "secret:file/event-hmac-key",
        4_000,
        4,
    );
    let valid = runtime_with_event_destinations(&fixture, &binding);
    parse_runtime_config_with_env(&valid, env_lookup).expect("strict event binding parses");
    parse_runtime_config_with_env(
        &valid.replace("  case-operations:\n", "  events:\n"),
        env_lookup,
    )
    .expect("a compiler-valid logical id is not mistaken for a governed member");

    for raw in [
        valid.replace(
            "    path: /hooks/registry\n",
            "    path: /hooks/registry\n    headers: {}\n",
        ),
        valid.replace(
            "      maximumAttempts: 4\n",
            "      maximumAttempts: 4\n      retryPolicy: caller-controlled\n",
        ),
        valid.replace(
            "    deliveryCeilings:\n",
            "    tls:\n      caBundleRef: secret:file/event-ca\n      privateKey: inline-canary\n    deliveryCeilings:\n",
        ),
    ] {
        assert_eq!(
            parse_runtime_config_with_env(&raw, env_lookup)
                .expect_err("unknown event destination key refused"),
            RuntimeConfigError::Document
        );
    }

    let mut governed = valid;
    governed.push_str("webhooks: []\n");
    assert_eq!(
        parse_runtime_config_with_env(&governed, env_lookup)
            .expect_err("governed webhooks refused"),
        RuntimeConfigError::GovernedMember
    );
}

#[test]
fn invalid_event_destination_ids_origins_paths_cidrs_refs_and_ceilings_are_refused() {
    let fixture = RuntimeFixture::new();
    let valid = runtime_with_event_destinations(
        &fixture,
        &event_destination_binding(
            "case-operations",
            "https://events.example/",
            "/hooks/registry",
            "secret:file/event-hmac-key",
            4_000,
            4,
        ),
    );
    let invalid_bindings = [
        valid.replace("  case-operations:\n", "  Case-operations:\n"),
        valid.replace("https://events.example/", "not-a-url"),
        valid.replace("https://events.example/", "http://events.example/"),
        valid.replace("https://events.example/", "https://events.example/path"),
        valid.replace("/hooks/registry", "//authority-smuggling"),
        valid.replace("/hooks/registry", "/hooks?query=denied"),
        valid.replace(
            "    allowedPrivateCidrs: []\n",
            "    allowedPrivateCidrs: [10.1.2.3/8]\n",
        ),
        valid.replace(
            "    allowedPrivateCidrs: []\n",
            "    allowedPrivateCidrs: [203.0.113.0/24]\n",
        ),
        valid.replace(
            "    allowedPrivateCidrs: []\n",
            "    allowedPrivateCidrs: [192.168.0.0/16, 10.0.0.0/8]\n",
        ),
        valid.replace(
            "secret:file/event-hmac-key",
            "secret:file/../event-hmac-key",
        ),
        valid.replace(
            "attemptTimeoutMilliseconds: 4000",
            "attemptTimeoutMilliseconds: 99",
        ),
        valid.replace(
            "attemptTimeoutMilliseconds: 4000",
            "attemptTimeoutMilliseconds: 10001",
        ),
        valid.replace("maximumAttempts: 4", "maximumAttempts: 0"),
        valid.replace("maximumAttempts: 4", "maximumAttempts: 21"),
        valid.replace(
            "    deliveryCeilings:\n",
            "    tls: {}\n    deliveryCeilings:\n",
        ),
    ];
    for raw in invalid_bindings {
        assert_eq!(
            parse_runtime_config_with_env(&raw, env_lookup)
                .expect_err("invalid event binding refused"),
            RuntimeConfigError::InvalidEventDestination
        );
    }

    for raw in [
        valid.replace("productionHttps", "privateServiceHttp"),
        valid.replace("dualStackStrict", "resolverDefault"),
    ] {
        assert_eq!(
            parse_runtime_config_with_env(&raw, env_lookup)
                .expect_err("non-closed event profile refused"),
            RuntimeConfigError::Document
        );
    }
}

#[cfg(not(feature = "postgres-test"))]
#[test]
fn pinned_loopback_https_event_profile_is_absent_without_postgres_test() {
    let fixture = RuntimeFixture::new();
    let raw = runtime_with_event_destinations(
        &fixture,
        &event_destination_binding(
            "case-operations",
            "https://127.0.0.1:1/",
            "/hooks/registry",
            "secret:file/event-hmac-key",
            2_500,
            3,
        )
        .replace("productionHttps", "pinnedLoopbackHttpsTest"),
    );

    assert_eq!(
        parse_runtime_config_with_env(&raw, env_lookup)
            .expect_err("test-only network profile is absent from production parsing"),
        RuntimeConfigError::Document
    );
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn pinned_loopback_https_event_profile_activates_with_exact_test_tls_and_ceilings() {
    const DESTINATION: &str = "case-operations";
    let fixture = RuntimeFixture::new();
    fixture.write_secret("event-hmac-key", &[0x41; 32]);
    let binding = event_destination_binding(
        DESTINATION,
        "https://127.0.0.1:1/",
        "/hooks/registry",
        "secret:file/event-hmac-key",
        2_500,
        3,
    )
    .replace("productionHttps", "pinnedLoopbackHttpsTest");
    let raw = runtime_with_event_destinations(&fixture, &binding);
    let compiled = compiled_webhooks(&[(DESTINATION, 5_000, 5)]);

    let activate = |runtime: &str| {
        parse_runtime_config_with_env(runtime, env_lookup)
            .expect("test-only loopback HTTPS binding parses")
            .activate_event_destinations(&compiled)
            .expect("test-only loopback HTTPS binding activates")
    };
    let first = activate(&raw);
    let second = activate(&raw);
    assert_eq!(first.binding_digest(), second.binding_digest());
    let destination = first
        .lookup(DESTINATION)
        .expect("compiled logical destination is activated");
    assert_eq!(
        destination.policy().dns_family(),
        DestinationDnsFamily::DualStackStrict
    );
    assert_eq!(destination.attempt_timeout(), Duration::from_millis(2_500));
    assert_eq!(destination.maximum_attempts(), 3);
    assert_eq!(
        destination.binding_digest(),
        second
            .lookup(DESTINATION)
            .expect("second activation has the exact destination")
            .binding_digest()
    );

    let production = activate(&raw.replace("pinnedLoopbackHttpsTest", "productionHttps"));
    assert_ne!(first.binding_digest(), production.binding_digest());
    assert_ne!(
        destination.binding_digest(),
        production
            .lookup(DESTINATION)
            .expect("production comparison binding activates")
            .binding_digest(),
        "the test-only TLS confinement profile is digest-bound"
    );

    let request = destination
        .request_template()
        .render_event(event_headers(), br#"{"label":"value"}"#.to_vec())
        .expect("closed event request renders");
    assert_eq!(
        destination
            .policy()
            .send(request, Duration::from_secs(1))
            .await
            .expect_err("closed loopback port has no TLS listener"),
        DestinationSendError::TransportFailed,
        "the pinned profile permits only the HTTPS transport attempt to loopback"
    );

    assert_eq!(
        parse_runtime_config_with_env(
            &raw.replace("https://127.0.0.1:1/", "http://127.0.0.1:1/"),
            env_lookup
        )
        .expect_err("the test profile never weakens HTTPS"),
        RuntimeConfigError::InvalidEventDestination
    );
}

#[test]
fn activation_constructs_the_exact_platform_policy_template_and_signing_material() {
    const ORIGIN_CANARY: &str = "event-origin-canary.example";
    const PATH_CANARY: &str = "/event-path-canary";
    const DESTINATION_CANARY: &str = "case-operations";
    const REF_CANARY: &str = "event-hmac-key";
    const KEY_CANARY: &[u8] = b"event-key-canary-012345678901234567890123456789";

    let fixture = RuntimeFixture::new();
    fixture.write_secret(REF_CANARY, KEY_CANARY);
    let raw = runtime_with_event_destinations(
        &fixture,
        &event_destination_binding(
            DESTINATION_CANARY,
            &format!("https://{ORIGIN_CANARY}/"),
            PATH_CANARY,
            &format!("secret:file/{REF_CANARY}"),
            4_000,
            4,
        ),
    );
    let config = parse_runtime_config_with_env(&raw, env_lookup).expect("runtime parses");
    let compiled = compiled_webhooks(&[(DESTINATION_CANARY, 5_000, 5)]);
    let activated = config
        .activate_event_destinations(&compiled)
        .expect("exact event binding activates");

    assert!(activated.binding_digest().starts_with("sha256:"));
    assert_eq!(activated.binding_digest().len(), 71);
    assert!(activated.lookup("substituted-destination").is_none());
    let destination = activated
        .lookup(DESTINATION_CANARY)
        .expect("compiled logical destination is active");
    assert_eq!(destination.policy().origin_id(), DESTINATION_CANARY);
    assert_eq!(
        destination.policy().dns_family(),
        DestinationDnsFamily::DualStackStrict
    );
    assert_eq!(destination.attempt_timeout(), Duration::from_secs(4));
    assert_eq!(destination.maximum_attempts(), 4);
    assert!(destination.binding_digest().starts_with("sha256:"));
    assert_eq!(destination.binding_digest().len(), 71);
    let destination_binding_digest = destination.binding_digest().to_owned();
    destination.with_hmac_sha256_key(|key| assert_eq!(key, KEY_CANARY));
    let request = destination
        .request_template()
        .render_event(event_headers(), br#"{"label":"value"}"#.to_vec())
        .expect("closed event request renders");

    let diagnostic = format!("{config:?} {activated:?} {destination:?} {request:?}");
    for canary in [
        ORIGIN_CANARY,
        PATH_CANARY,
        DESTINATION_CANARY,
        REF_CANARY,
        std::str::from_utf8(KEY_CANARY).expect("key canary is text"),
        "label\":\"value",
    ] {
        assert!(!diagnostic.contains(canary), "debug leaked {canary}");
    }

    fixture.write_secret(REF_CANARY, &[0x5a; 32]);
    let same_references = config
        .activate_event_destinations(&compiled)
        .expect("rotated key activates under the same reference");
    assert_eq!(
        destination_binding_digest,
        same_references
            .lookup(DESTINATION_CANARY)
            .expect("rotated destination remains active")
            .binding_digest(),
        "binding identity must never digest secret bytes"
    );
}

#[test]
fn activation_requires_exact_compiled_and_runtime_destination_sets() {
    let fixture = RuntimeFixture::new();
    let compiled = compiled_webhooks(&[("case-operations", 5_000, 5)]);

    let missing = parse_runtime_config_with_env(
        &valid_runtime(
            &fixture.secret_root,
            &fixture.package_root,
            &fixture.trust_anchor,
        ),
        env_lookup,
    )
    .expect("empty runtime parses");
    assert_eq!(
        missing
            .activate_event_destinations(&compiled)
            .expect_err("missing binding refused"),
        EventDestinationActivationError::InventoryMismatch
    );

    for bindings in [
        event_destination_binding(
            "substituted-destination",
            "https://events.example/",
            "/hooks/registry",
            "secret:file/missing-key",
            4_000,
            4,
        ),
        format!(
            "{}{}",
            event_destination_binding(
                "case-operations",
                "https://events.example/",
                "/hooks/registry",
                "secret:file/missing-key",
                4_000,
                4,
            ),
            event_destination_binding(
                "extra-destination",
                "https://extra.example/",
                "/hooks/extra",
                "secret:file/missing-key",
                4_000,
                4,
            )
        ),
    ] {
        let config = parse_runtime_config_with_env(
            &runtime_with_event_destinations(&fixture, &bindings),
            env_lookup,
        )
        .expect("binding set parses");
        assert_eq!(
            config
                .activate_event_destinations(&compiled)
                .expect_err("non-exact binding set refused before secret lookup"),
            EventDestinationActivationError::InventoryMismatch
        );
    }
}

#[test]
fn runtime_destination_classification_ceiling_cannot_widen_compiled_event_disclosure() {
    let fixture = RuntimeFixture::new();
    fixture.write_secret("event-hmac-key", &[0x41; 32]);
    let compiled = compiled_webhooks(&[
        ("shared-destination", 5_000, 5),
        ("shared-destination", 3_000, 3),
    ]);

    let compatible = parse_runtime_config_with_env(
        &runtime_with_event_destinations(
            &fixture,
            &event_destination_binding(
                "shared-destination",
                "https://events.example/",
                "/hooks/shared",
                "secret:file/event-hmac-key",
                2_500,
                3,
            ),
        ),
        env_lookup,
    )
    .expect("compatible shared binding parses");
    let activated = compatible
        .activate_event_destinations(&compiled)
        .expect("one narrowing ceiling is compatible with every subscription");
    assert_eq!(
        activated
            .lookup("shared-destination")
            .expect("shared destination is active")
            .attempt_timeout(),
        Duration::from_millis(2_500)
    );

    let below_compiled_classification = runtime_with_event_destinations(
        &fixture,
        &event_destination_binding(
            "shared-destination",
            "https://events.example/",
            "/hooks/shared",
            "secret:file/event-hmac-key",
            2_500,
            3,
        ),
    )
    .replace(
        "classificationCeiling: restricted",
        "classificationCeiling: public",
    );
    let below_compiled_classification =
        parse_runtime_config_with_env(&below_compiled_classification, env_lookup)
            .expect("lower classification ceiling parses");
    assert_eq!(
        below_compiled_classification
            .activate_event_destinations(&compiled)
            .expect_err("runtime destination cannot accept a higher-classified event"),
        EventDestinationActivationError::DeliveryCeilingWidening
    );
}

#[test]
fn event_destination_digest_is_deterministic_across_yaml_map_order() {
    let fixture = RuntimeFixture::new();
    fixture.write_secret("alpha-key", &[0x41; 32]);
    fixture.write_secret("alpha-key-rotated-reference", &[0x41; 32]);
    fixture.write_secret("bravo-key", &[0x42; 32]);
    fixture.write_secret("bravo-key-rotated-reference", &[0x42; 32]);
    let alpha = event_destination_binding(
        "alpha-destination",
        "https://alpha.example/",
        "/hooks/alpha",
        "secret:file/alpha-key",
        3_000,
        3,
    );
    let bravo = event_destination_binding(
        "bravo-destination",
        "https://bravo.example/",
        "/hooks/bravo",
        "secret:file/bravo-key",
        4_000,
        4,
    );
    let compiled = compiled_webhooks(&[
        ("alpha-destination", 5_000, 5),
        ("bravo-destination", 5_000, 5),
    ]);

    let activate = |bindings: String| {
        parse_runtime_config_with_env(
            &runtime_with_event_destinations(&fixture, &bindings),
            env_lookup,
        )
        .expect("ordered runtime parses")
        .activate_event_destinations(&compiled)
        .expect("ordered runtime activates")
    };
    let first = activate(format!("{alpha}{bravo}"));
    let second = activate(format!("{bravo}{alpha}"));
    assert_eq!(first.binding_digest(), second.binding_digest());
    assert!(first.lookup("alpha-destination").is_some());
    assert!(first.lookup("bravo-destination").is_some());
    assert!(first.lookup("charlie-destination").is_none());

    let changed_alpha_reference = activate(format!("{alpha}{bravo}").replace(
        "secret:file/alpha-key\n",
        "secret:file/alpha-key-rotated-reference\n",
    ));
    assert_ne!(
        first.binding_digest(),
        changed_alpha_reference.binding_digest()
    );
    assert_ne!(
        first
            .lookup("alpha-destination")
            .expect("alpha is active")
            .binding_digest(),
        changed_alpha_reference
            .lookup("alpha-destination")
            .expect("changed alpha is active")
            .binding_digest()
    );

    let changed_bravo_reference = activate(format!("{alpha}{bravo}").replace(
        "secret:file/bravo-key\n",
        "secret:file/bravo-key-rotated-reference\n",
    ));
    assert_ne!(
        first.binding_digest(),
        changed_bravo_reference.binding_digest()
    );
    assert_eq!(
        first
            .lookup("alpha-destination")
            .expect("alpha is active")
            .binding_digest(),
        changed_bravo_reference
            .lookup("alpha-destination")
            .expect("unchanged alpha is active")
            .binding_digest(),
        "an unrelated destination must not invalidate alpha"
    );
}

#[test]
fn event_destination_missing_oversized_and_unsafe_secrets_fail_value_free() {
    const SECRET_CANARY: &str = "event-secret-reference-canary";

    let fixture = RuntimeFixture::new();
    let compiled = compiled_webhooks(&[("case-operations", 5_000, 5)]);
    for (key_ref, tls) in [
        (format!("secret:file/{SECRET_CANARY}"), "".to_owned()),
        (
            "secret:file/event-hmac-key".to_owned(),
            format!("    tls:\n      caBundleRef: secret:file/{SECRET_CANARY}\n"),
        ),
    ] {
        if !tls.is_empty() {
            fixture.write_secret("event-hmac-key", &[0x41; 32]);
        }
        let binding = event_destination_binding(
            "case-operations",
            "https://events.example/",
            "/hooks/registry",
            &key_ref,
            4_000,
            4,
        )
        .replace(
            "    deliveryCeilings:\n",
            &format!("{tls}    deliveryCeilings:\n"),
        );
        let config = parse_runtime_config_with_env(
            &runtime_with_event_destinations(&fixture, &binding),
            env_lookup,
        )
        .expect("secret-ref runtime parses");
        let error = config
            .activate_event_destinations(&compiled)
            .expect_err("missing secret refused");
        assert_eq!(error, EventDestinationActivationError::Secret);
        assert!(!format!("{error:?} {error}").contains(SECRET_CANARY));
    }

    let oversized_key = vec![0x51; 64 * 1024 + 1];
    fixture.write_secret("oversized-event-key", &oversized_key);
    let oversized = parse_runtime_config_with_env(
        &runtime_with_event_destinations(
            &fixture,
            &event_destination_binding(
                "case-operations",
                "https://events.example/",
                "/hooks/registry",
                "secret:file/oversized-event-key",
                4_000,
                4,
            ),
        ),
        env_lookup,
    )
    .expect("oversized secret ref parses");
    assert_eq!(
        oversized
            .activate_event_destinations(&compiled)
            .expect_err("oversized secret refused by the shared loader"),
        EventDestinationActivationError::Secret
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fixture.write_secret("unsafe-event-key", &[0x52; 32]);
        fs::set_permissions(
            fixture.secret_root.join("unsafe-event-key"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("unsafe permissions set");
        let unsafe_file = parse_runtime_config_with_env(
            &runtime_with_event_destinations(
                &fixture,
                &event_destination_binding(
                    "case-operations",
                    "https://events.example/",
                    "/hooks/registry",
                    "secret:file/unsafe-event-key",
                    4_000,
                    4,
                ),
            ),
            env_lookup,
        )
        .expect("unsafe secret ref parses");
        assert_eq!(
            unsafe_file
                .activate_event_destinations(&compiled)
                .expect_err("unsafe secret file refused by the shared loader"),
            EventDestinationActivationError::Secret
        );
    }
}

#[tokio::test]
async fn production_event_policy_refuses_literal_metadata_and_unallowed_private_destinations() {
    let fixture = RuntimeFixture::new();
    fixture.write_secret("event-hmac-key", &[0x41; 32]);
    let compiled = compiled_webhooks(&[("case-operations", 5_000, 5)]);

    for (origin, expected) in [
        (
            "https://169.254.169.254/",
            DestinationSendError::CloudMetadataDenied,
        ),
        (
            "https://10.20.30.40/",
            DestinationSendError::PrivateAddressNotAllowed,
        ),
    ] {
        let config = parse_runtime_config_with_env(
            &runtime_with_event_destinations(
                &fixture,
                &event_destination_binding(
                    "case-operations",
                    origin,
                    "/hooks/registry",
                    "secret:file/event-hmac-key",
                    4_000,
                    4,
                ),
            ),
            env_lookup,
        )
        .expect("literal HTTPS binding parses");
        let activated = config
            .activate_event_destinations(&compiled)
            .expect("literal HTTPS binding activates under platform authority");
        let destination = activated
            .lookup("case-operations")
            .expect("compiled destination is active");
        let request = destination
            .request_template()
            .render_event(event_headers(), br#"{"label":"value"}"#.to_vec())
            .expect("event request renders");
        let error = destination
            .policy()
            .send(request, Duration::from_secs(1))
            .await
            .expect_err("platform policy refuses the literal address");
        assert_eq!(error, expected);
        let rendered = format!("{error:?} {error} {activated:?}");
        assert!(!rendered.contains(origin));
    }
}

fn env_lookup(name: &str) -> Option<String> {
    match name {
        "REGISTRY_SERVER_RUNTIME_CONFIG_DATABASE_URL" => Some(DATABASE_URL_CANARY.to_owned()),
        "REGISTRY_SERVER_RUNTIME_CONFIG_MIGRATION_DATABASE_URL" => {
            Some(MIGRATION_DATABASE_URL_CANARY.to_owned())
        }
        _ => None,
    }
}

fn runtime_with_discovery_source(fixture: &RuntimeFixture) -> String {
    valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace(
        "    jwksCache:\n",
        "    jwksSource:\n      kind: discovery\n    jwksCache:\n",
    )
}

fn runtime_with_static_jwks_ref(fixture: &RuntimeFixture, document_ref: &str) -> String {
    valid_runtime(
        &fixture.secret_root,
        &fixture.package_root,
        &fixture.trust_anchor,
    )
    .replace(
        "    jwksCache:\n",
        &format!("    jwksSource:\n      kind: static\n      documentRef: {document_ref}\n    jwksCache:\n"),
    )
}

fn static_jwks_document(keys: &[Value]) -> String {
    let document = json!({ "keys": keys });
    serde_json::to_string(&document).expect("test JWKS serializes")
}

fn static_ed25519_jwk(kid: &str) -> Value {
    let mut public = PrivateJwk::parse(registry_platform_testing::fixtures::ED25519_PRIVATE_JWK)
        .expect("fixture private JWK parses")
        .public();
    public.kid = Some(kid.to_owned());
    serde_json::to_value(public).expect("public JWK serializes")
}

fn es256_jwk_with_point(kid: &str, x: Vec<u8>, y: Vec<u8>) -> Value {
    json!({
        "kty": "EC",
        "kid": kid,
        "alg": "ES256",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    })
}

fn rsa_jwk(kid: &str, modulus_bytes: usize, exponent: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(vec![0xff; modulus_bytes]),
        "e": exponent,
    })
}

fn with_member(mut value: Value, member: &str, replacement: Value) -> Value {
    value
        .as_object_mut()
        .expect("test JWK is an object")
        .insert(member.to_owned(), replacement);
    value
}

fn without_member(mut value: Value, member: &str) -> Value {
    value
        .as_object_mut()
        .expect("test JWK is an object")
        .remove(member);
    value
}

fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn async_environment_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

struct RuntimeFixture {
    root: PathBuf,
    secret_root: PathBuf,
    package_root: PathBuf,
    trust_anchor: PathBuf,
}

impl RuntimeFixture {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes")
            .join(format!(
                "registry-server-runtime-config-test-{suffix}-{}-{counter}",
                std::process::id()
            ));
        fs::create_dir(&root).expect("temporary fixture root creates");
        let secret_root = root.join("secrets");
        let package_root = root.join("package");
        fs::create_dir(&secret_root).expect("secret root creates");
        fs::create_dir(&package_root).expect("package root creates");
        let trust_anchor = root.join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("trust anchor placeholder writes");
        fs::write(secret_root.join("audit-key"), AUDIT_KEY_CANARY).expect("audit secret writes");
        fs::write(secret_root.join("cursor-key"), [0x52_u8; 32]).expect("cursor secret writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                secret_root.join("audit-key"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("audit secret permissions set");
            fs::set_permissions(
                secret_root.join("cursor-key"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("cursor secret permissions set");
        }
        Self {
            root,
            secret_root,
            package_root,
            trust_anchor,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write_secret(&self, name: &str, bytes: &[u8]) {
        let path = self.secret_root.join(name);
        fs::write(&path, bytes).expect("event secret writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("event secret permissions set");
        }
    }
}

impl Drop for RuntimeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
