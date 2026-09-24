// SPDX-License-Identifier: Apache-2.0

//! Consent acceptance journeys for the product fixtures that
//! `bregctl module add consent` generated: a person registry and a land
//! registry whose tenure rights a lender reads. Each fixture runs its journeys
//! through the authenticated PostgreSQL router and the schema-test receipt.

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml, RegistryProject};
use registry_breg::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package, FixtureError,
    FixtureModuleSource, FixtureSourceFile, PostgresFixtureTestRunner, SchemaTestSources,
    ValidatedFixtureJourneys,
};
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, PreparedPackage, SignaturePolicy, TrustAnchorKey, VerifiedPackage,
    FIXTURE_JOURNEYS_PATH, TRUST_ANCHOR_API_VERSION,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_breg::startup::{prepare_with_connection_config_for_test, PreparedServer};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{fixtures as testing_fixtures, jwks_from_private_jwk, MockIdp};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;
use tower::Service as _;

const AUDIENCE: &str = "urn:breg:consent-examples";
// The journey sources write every timestamp that must be in force at run time
// on this date. The harness rebases it to the day before the run, because the
// runtime evaluates consent validity against the database clock and the
// fixtures' 365-day maxDuration would otherwise retire those gives.
const ANCHOR_DATE_PREFIX: &str = "2026-09-01T";
// The client a token carries when the journey step names no requester client:
// the self, steward, and feed profiles bind no client, so any allowed client
// may call them. The recipient feed is the exception: its rows follow the
// client's recipient set, so feed principals map to their recipient's client.
const CONSENT_PORTAL_CLIENT: &str = "consent-portal";
// Each fixture owns the process-global configured WASM runtime until finish.
static WASM_RUNTIME_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn person_registry_consent_journeys_run_through_the_authenticated_postgres_runner() {
    let fixture = RunningFixture::start(
        "consent-person-registry",
        &[
            ("synthetic-food-agency-feed", "food-agency-portal"),
            ("synthetic-health-ngo-feed", "health-ngo-portal"),
        ],
    )
    .await;
    let receipt_journeys = fixture.run_journeys().await;
    assert_eq!(
        receipt_journeys,
        [
            "group-recipient-and-assisted-capture",
            "refusal-future-give-and-expiry",
            "self-give-read-withdraw-and-backdated-regive",
        ]
    );
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn land_registry_consent_journeys_run_through_the_authenticated_postgres_runner() {
    let fixture = RunningFixture::start(
        "consent-land-registry",
        &[
            ("synthetic-lender-a-feed", "lender-a-portal"),
            ("synthetic-lender-b-feed", "lender-b-portal"),
        ],
    )
    .await;
    let receipt_journeys = fixture.run_journeys().await;
    assert_eq!(
        receipt_journeys,
        ["lender-reads-a-tenure-right-only-under-consent"]
    );
    fixture.finish().await;
}

/// Spec section 12: the self actions carry a subject target with empty row
/// boundaries, so a self caller could probe whether a subject id exists if an
/// unknown id answered differently from an existing subject the caller's link
/// does not cover. Both must produce the same response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_action_answers_an_unknown_subject_like_a_subject_its_link_does_not_cover() {
    let fixture = RunningFixture::start("consent-person-registry", &[]).await;
    let app = fixture.prepared.app();
    let steward = fixture.token(json!({
        "registry_principal": "synthetic-consent-steward",
        "scope": "consent:person:steward",
    }));
    let operator = fixture.token(json!({
        "registry_principal": "synthetic-registry-operator",
        "registry_actor_kind": "human",
        "azp": "person-registry-console",
        "scope": "registry:person:operate",
    }));
    let link_steward = fixture.token(json!({
        "registry_principal": "synthetic-link-steward",
        "scope": "consent:person:link",
    }));
    let self_token = fixture.token(json!({
        "registry_principal": "oracle-self",
        "scope": "consent:person:self",
    }));

    let notice = create(
        &app,
        "person-privacy-notices",
        "person-consent-steward",
        &steward,
        json!({
            "noticeVersion": "2026.1", "language": "en", "title": "Oracle notice",
            "controllerName": "Person Registry Authority",
            "controllerContact": "privacy@consent-person-registry.example.gov",
            "jurisdiction": "Solmara", "legalBasis": "Consent.",
            "withdrawalMethod": "Withdraw at any office.",
            "publishedAt": "2026-01-01T00:00:00Z",
        }),
    )
    .await;
    let clause = create(
        &app,
        "person-notice-clauses",
        "person-consent-steward",
        &steward,
        json!({
            "notice": notice, "recipient": "food-agency", "purpose": "food-assistance",
            "scope": "food-targeting", "description": "Oracle clause.",
        }),
    )
    .await;
    let own = create(
        &app,
        "persons",
        "person-registry-operator",
        &operator,
        json!({"personCode": "P-ORACLE-OWN", "legalName": "Oracle Own", "district": "north"}),
    )
    .await;
    let other = create(
        &app,
        "persons",
        "person-registry-operator",
        &operator,
        json!({"personCode": "P-ORACLE-OTHER", "legalName": "Oracle Other", "district": "north"}),
    )
    .await;
    let link = create(
        &app,
        "person-consent-links",
        "person-consent-link-steward",
        &link_steward,
        json!({"subject": own, "principal": "oracle-self", "active": true}),
    )
    .await;

    let give = |subject: &str, key: &str| {
        let input = json!({
            "link": link, "subject": subject, "clause": clause,
            "recipient": "food-agency", "purpose": "food-assistance",
            "scope": "food-targeting", "decision": "given", "channel": "self-service",
            "effectiveAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2099-12-31T00:00:00Z",
        });
        send(
            app.clone(),
            Method::POST,
            "/v1/actions/give-person-consent?accessProfile=person-consent-self".to_owned(),
            json!({"input": input}),
            Some(key.to_owned()),
            self_token.clone(),
        )
    };
    let unknown = give("7f3c9a52-4f0e-4d8b-9a61-2b5e8c1d0f47", "oracle-unknown").await;
    let uncovered = give(&other, "oracle-uncovered").await;
    assert_eq!(
        unknown.0,
        StatusCode::PRECONDITION_FAILED,
        "unknown subject: {}",
        unknown.1
    );
    assert_eq!(
        unknown.0, uncovered.0,
        "unknown: {} uncovered: {}",
        unknown.1, uncovered.1
    );
    assert_eq!(
        without_trace(unknown.1),
        without_trace(uncovered.1),
        "an unknown subject and an existing subject outside the caller's link answer alike"
    );
    // Control: the same action and link succeed for the subject the link covers.
    let covered = give(&own, "oracle-covered").await;
    assert_eq!(covered.0, StatusCode::OK, "covered subject: {}", covered.1);
    fixture.finish().await;
}

struct RunningFixture {
    runtime_guard: tokio::sync::MutexGuard<'static, ()>,
    database: TestDatabase,
    registry: Arc<CompiledRegistry>,
    prepared: PreparedServer,
    idp: MockIdp,
    package: TestPackage,
    sources: ExampleSources,
    feed_clients: BTreeMap<String, String>,
}

impl RunningFixture {
    async fn start(name: &str, feed_clients: &[(&str, &str)]) -> Self {
        let runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
        let sources = ExampleSources::load(name);
        let registry = Arc::new(sources.compiled.clone());
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("administrator installs the compiler-owned consent example schema");
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("managed schema fingerprint computes for the consent example");
        let package = TestPackage::build(&sources, &schema_fingerprint);
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: &package.package.manifest().package_id,
                environment: &package.package.manifest().environment,
                instance_id: &package.package.manifest().instance_id,
                database_id: &package.package.manifest().database_id,
                package_revision: &package.package.manifest().package_revision,
                package_sequence: 1,
            },
        )
        .await
        .expect("database initializes from the exact signed consent example identity");
        drop(migration);
        migration_task.abort();

        let idp = MockIdp::start().await;
        let config_path =
            package.write_runtime_config(&database, &idp, &allowed_clients(&registry));
        let prepared =
            prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
                .await
                .expect("verified startup constructs the authenticated consent example runtime");

        Self {
            runtime_guard,
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
            feed_clients: feed_clients
                .iter()
                .map(|(principal, client)| ((*principal).to_owned(), (*client).to_owned()))
                .collect(),
        }
    }

    /// Validate, run, and receipt every journey; return the receipt's
    /// successful journey ids.
    async fn run_journeys(&self) -> Vec<String> {
        let suite = validate_fixture_journeys(&self.sources.journeys, &self.registry)
            .unwrap_or_else(|error| {
                panic!(
                    "consent journeys preflight against the Production registry: {}",
                    fixture_error_with_source_context(&self.sources.journeys, &error)
                )
            });
        let tokens = self.journey_tokens(&suite);
        let runner =
            prepare_runner(&self.package, &self.sources, &suite, &self.prepared, tokens).await;
        let completed = runner.run_all().await.unwrap_or_else(|error| {
            panic!(
                "consent journeys execute through the authenticated PostgreSQL router: {}",
                fixture_error_with_source_context(&self.sources.journeys, &error)
            )
        });
        let receipt = completed
            .build_receipt(&suite)
            .expect("consent execution emits a bound schema-test receipt");
        let receipt_bytes = receipt.canonical_bytes().expect("receipt canonicalizes");
        validate_schema_test_receipt_for_package(&receipt_bytes, &self.package.prepared, &suite)
            .expect("consent receipt revalidates against the exact prepared package");
        receipt.successful_journey_ids().to_vec()
    }

    /// Mint one bearer token per journey step, in source order, from the
    /// step's own declared claims. The client comes from the step's requester
    /// client, else the feed principal's recipient client, else the portal.
    fn journey_tokens(&self, suite: &ValidatedFixtureJourneys) -> Vec<String> {
        let source: Value = serde_norway::from_slice(&self.sources.journeys)
            .expect("consent journey source converts to a JSON value");
        let journeys = source["journeys"]
            .as_array()
            .expect("consent journey source lists journeys");
        assert_eq!(
            journeys
                .iter()
                .map(|journey| journey["id"].as_str().expect("journey id"))
                .collect::<Vec<_>>(),
            suite.journey_ids(),
            "source and validated journey order must match before assigning bearer tokens"
        );
        journeys
            .iter()
            .flat_map(|journey| {
                journey["steps"]
                    .as_array()
                    .expect("consent journey lists steps")
            })
            .map(|step| {
                let claims = &step["claims"];
                let principal = claims["principal"]
                    .as_str()
                    .expect("every consent journey step names a principal");
                let client = claims["requesterClient"]
                    .as_str()
                    .or_else(|| self.feed_clients.get(principal).map(String::as_str))
                    .unwrap_or(CONSENT_PORTAL_CLIENT);
                let scopes = claims["scopes"]
                    .as_array()
                    .expect("every consent journey step names its scopes")
                    .iter()
                    .map(|scope| scope.as_str().expect("scope is a string"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut token = json!({
                    "registry_principal": principal,
                    "registry_actor_kind": claims["actorKind"].as_str().unwrap_or("service"),
                    "azp": client,
                    "scope": scopes,
                });
                if let Some(purpose) = claims["purpose"].as_str() {
                    token["purpose"] = json!(purpose);
                }
                if let Some(direct) = claims["directClaims"].as_object() {
                    for (name, value) in direct {
                        token[name] = value.clone();
                    }
                }
                self.token(token)
            })
            .collect()
    }

    fn token(&self, mut claims: Value) -> String {
        claims["aud"] = json!(AUDIENCE);
        if claims.get("registry_actor_kind").is_none() {
            claims["registry_actor_kind"] = json!("service");
        }
        if claims.get("azp").is_none() {
            claims["azp"] = json!(CONSENT_PORTAL_CLIENT);
        }
        self.idp.mint_token(claims)
    }

    async fn finish(self) {
        let Self {
            runtime_guard,
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
            feed_clients: _,
        } = self;
        drop(prepared);
        drop(registry);
        drop(package);
        drop(sources);
        idp.stop().await;
        database.cleanup().await;
        drop(runtime_guard);
    }
}

/// Every recipient client, every client a profile admits, and the portal.
fn allowed_clients(registry: &CompiledRegistry) -> Vec<String> {
    let mut clients = registry
        .recipients()
        .clients()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for client in [
        "person-registry-console",
        "land-registry-console",
        CONSENT_PORTAL_CLIENT,
    ] {
        clients.push(client.to_owned());
    }
    clients.sort();
    clients.dedup();
    clients
}

struct ExampleSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    modules: Vec<ExampleModule>,
    journeys: Vec<u8>,
    compiled: CompiledRegistry,
}

struct ExampleModule {
    id: String,
    path: String,
    bytes: Vec<u8>,
}

impl ExampleSources {
    fn load(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/fixtures")
            .join(name);
        let project_bytes =
            fs::read(root.join("registry.yaml")).expect("consent example registry is readable");
        let project = parse_project_yaml(&project_bytes)
            .expect("consent example registry follows the strict authoring contract");
        let mut modules = Vec::new();
        let mut parsed_modules = Vec::new();
        for locked in &project.modules {
            let path = format!("modules/{}/module.yaml", locked.id);
            let bytes = fs::read(root.join(&path)).expect("locked consent module is readable");
            let module = parse_module_yaml(&bytes)
                .expect("locked consent module follows the strict authoring contract");
            modules.push(ExampleModule {
                id: locked.id.clone(),
                path,
                bytes,
            });
            parsed_modules.push(module);
        }
        let compiled =
            compile_project_with_assets(&project, &parsed_modules, &[], CompileProfile::Production)
                .expect("consent example closes under the Production compiler");
        let journeys = rebase_anchor_date(
            &fs::read(root.join("tests/journeys.yaml")).expect("consent journeys are readable"),
        );
        Self {
            project,
            project_bytes,
            modules,
            journeys,
            compiled,
        }
    }
}

fn rebase_anchor_date(source: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(source).expect("consent journey source is UTF-8");
    assert!(
        text.contains(ANCHOR_DATE_PREFIX),
        "consent journeys write in-force timestamps on the anchor date"
    );
    let yesterday = (OffsetDateTime::now_utc() - time::Duration::days(1)).date();
    let rebased = format!(
        "{:04}-{:02}-{:02}T",
        yesterday.year(),
        u8::from(yesterday.month()),
        yesterday.day()
    );
    text.replace(ANCHOR_DATE_PREFIX, &rebased).into_bytes()
}

struct TestPackage {
    _root: TempDir,
    directory: PathBuf,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    prepared: PreparedPackage,
    package: VerifiedPackage,
    migration_plan: Vec<u8>,
}

impl TestPackage {
    fn build(sources: &ExampleSources, schema_fingerprint: &str) -> Self {
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("consent example declares package identity");
        let database_id = format!("{}-database", sources.project.registry.id);
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("consent example package signing key generates");
        let key_id = signing.public().kid.expect("generated signing key has kid");
        let prepared = prepare_package(PackageBuildRequest {
            environment: identity.environment.clone(),
            instance_id: identity.instance_id.clone(),
            database_id: database_id.clone(),
            sequence: identity.sequence,
            prior_revision: None,
            compiler_source_revision: identity.source_revision.clone(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "registry.yaml".to_owned(),
                bytes: sources.project_bytes.clone(),
            },
            modules: sources
                .modules
                .iter()
                .map(|module| PackageModuleSource {
                    id: module.id.clone(),
                    path: module.path.clone(),
                    bytes: module.bytes.clone(),
                    assets: Vec::new(),
                })
                .collect(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: sources.journeys.clone(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("consent example package prepares from exact sources");
        let migration_plan = prepared
            .file_bytes()
            .get("database/migration-plan.json")
            .expect("prepared consent example package includes migration plan")
            .clone();
        let root = tempfile::tempdir().expect("temporary consent example package root creates");
        let directory = root
            .path()
            .canonicalize()
            .expect("temporary package root canonicalizes");
        let package_root = directory.join("package");
        let revision = prepared.package_revision().to_owned();
        let signature =
            sign(prepared.canonical_signed_bytes(), &signing).expect("package bytes sign");
        prepared
            .publish_to_directory(
                &package_root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("signed consent example package publishes");
        let anchor = directory.join("trust-anchor.json");
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: identity.environment.clone(),
                instance_id: identity.instance_id.clone(),
                database_id: database_id.clone(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public())
                        .expect("public signing JWK serializes"),
                }],
            },
        );
        let package = load_package(
            &package_root,
            &PackageLoadContext {
                environment: &identity.environment,
                instance_id: &identity.instance_id,
                database_id: &database_id,
                database_initialization_environment: &identity.environment,
                compiler_source_revision: &identity.source_revision,
                trust_anchor: Some(&anchor),
                intent: PackageIntent::InitialActivation,
            },
        )
        .expect("published consent example package rederives and verifies");
        assert_eq!(package.registry(), &sources.compiled);
        Self {
            _root: root,
            directory,
            package_root,
            anchor,
            revision,
            prepared,
            package,
            migration_plan,
        }
    }

    fn write_runtime_config(
        &self,
        database: &TestDatabase,
        idp: &MockIdp,
        allowed_clients: &[String],
    ) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("consent example secret root creates");
        write_private(&secrets.join("database-url"), b"unused-by-test-startup");
        write_private(&secrets.join("audit-key"), &[0x71; 32]);
        write_private(&secrets.join("cursor-key"), &[0x52; 32]);
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                    .expect("test IdP key parses"),
            ))
            .expect("static JWKS serializes"),
        );
        let identity = self.package.manifest();
        let allowed_clients = serde_json::to_string(allowed_clients).expect("clients serialize");
        let path = self.directory.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: {}
  instanceId: {}
  databaseId: {}
  databaseInitializationEnvironment: {}
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {}
  activeRevision: {}
  activeSequence: {}
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: {allowed_clients}
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
                identity.environment,
                identity.instance_id,
                identity.database_id,
                identity.environment,
                secrets.display(),
                database.migration_role.as_str(),
                database.runtime_role.as_str(),
                self.package_root.display(),
                self.anchor.display(),
                identity.compiler.source_revision,
                self.revision,
                identity.sequence,
                idp.issuer(),
            ),
        )
        .expect("strict consent example runtime configuration writes");
        set_private_permissions(&path);
        path
    }
}

async fn prepare_runner(
    package: &TestPackage,
    sources: &ExampleSources,
    suite: &ValidatedFixtureJourneys,
    prepared: &PreparedServer,
    bearer_tokens: Vec<String>,
) -> PostgresFixtureTestRunner {
    let modules = sources
        .modules
        .iter()
        .map(|module| FixtureModuleSource {
            id: module.id.as_str(),
            path: module.path.as_str(),
            bytes: module.bytes.as_slice(),
            assets: &[],
        })
        .collect::<Vec<_>>();
    PostgresFixtureTestRunner::prepare(
        &package.package,
        &SchemaTestSources {
            project: FixtureSourceFile {
                path: "registry.yaml",
                bytes: &sources.project_bytes,
            },
            project_assets: &[],
            modules: &modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &package.migration_plan,
            },
        },
        suite,
        prepared,
        bearer_tokens,
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "consent example runner derives exact package and same-database facts: {}",
            fixture_error_with_source_context(&sources.journeys, &error)
        )
    })
}

fn fixture_error_with_source_context(journey_source: &[u8], error: &FixtureError) -> String {
    if let FixtureError::StepFailed {
        journey_index,
        step_index,
        ..
    } = error
    {
        let source: Value =
            serde_norway::from_slice(journey_source).expect("journey source converts");
        if let Some(step) = source["journeys"][*journey_index]["steps"][*step_index]["id"].as_str()
        {
            let journey = source["journeys"][*journey_index]["id"]
                .as_str()
                .unwrap_or("?");
            return format!("{journey}.{step}: {error}");
        }
    }
    error.to_string()
}

async fn create(
    app: &axum::Router,
    route: &str,
    profile: &str,
    token: &str,
    data: Value,
) -> String {
    let (status, body) = send(
        app.clone(),
        Method::POST,
        format!("/v1/records/{route}?accessProfile={profile}"),
        json!({"data": data}),
        Some(format!("create-{route}-{}", data_digest(&data))),
        token.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{route}: {body}");
    body["data"]["recordIdentifier"]
        .as_str()
        .expect("created record has an identifier")
        .to_owned()
}

fn data_digest(data: &Value) -> String {
    let bytes = canonicalize_json(data).expect("create data canonicalizes");
    hex(&Sha256::digest(bytes)[..12])
}

async fn send(
    mut app: axum::Router,
    method: Method,
    uri: String,
    body: Value,
    idempotency_key: Option<String>,
    token: String,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    let request = request
        .body(Body::from(
            serde_json::to_vec(&body).expect("body serializes"),
        ))
        .expect("request builds");
    let response = app.call(request).await.expect("router answers");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body reads");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("response body is JSON")
    };
    (status, body)
}

/// A problem body with its per-request correlation removed.
fn without_trace(mut body: Value) -> Value {
    if let Some(object) = body.as_object_mut() {
        object.remove("traceId");
        object.remove("instance");
    }
    body
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private consent example file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private consent example file permissions set");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
