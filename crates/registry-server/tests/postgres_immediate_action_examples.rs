// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use postgres_harness::TestDatabase;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{fixtures as testing_fixtures, jwks_from_private_jwk, MockIdp};
use registry_server::compiler::{compile_project_with_assets, CompileProfile};
use registry_server::contract::{parse_module_yaml, parse_project_yaml, RegistryProject};
use registry_server::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package, FixtureError,
    FixtureModuleSource, FixtureSourceFile, PostgresFixtureTestRunner, SchemaTestSources,
    ValidatedFixtureJourneys,
};
use registry_server::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, PreparedPackage, SignaturePolicy, TrustAnchorKey, VerifiedPackage,
    FIXTURE_JOURNEYS_PATH, TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_server::startup::{prepare_with_connection_config_for_test, PreparedServer};
use registry_server::CompiledRegistry;
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::TempDir;

const AUDIENCE: &str = "urn:registry-server:immediate-action-examples";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn asset_registration_action_example_runs_through_authenticated_postgres_fixture_runner() {
    let fixture = RunningFixture::start("asset-registration-actions").await;
    assert_action_profile_has_no_crud_route(&fixture.registry, "asset-action-registrar");

    let suite = validate_fixture_journeys(&fixture.sources.journeys, &fixture.registry)
        .unwrap_or_else(|error| {
            panic!(
                "asset action journeys preflight against the Production registry: {}",
                fixture_error_with_source_context(&fixture.sources.journeys, &error)
            )
        });
    let runner = prepare_runner(
        &fixture.package,
        &fixture.sources,
        &suite,
        &fixture.prepared,
        asset_registration_tokens(&fixture.sources.journeys, &suite, &fixture.idp),
    )
    .await;
    let completed = runner.run_all().await.unwrap_or_else(|error| {
        panic!(
            "asset action journeys execute through the authenticated PostgreSQL router: {}",
            fixture_error_with_source_context(&fixture.sources.journeys, &error)
        )
    });
    let receipt = completed
        .build_receipt(&suite)
        .expect("asset action execution emits a bound schema-test receipt");
    let receipt_bytes = receipt.canonical_bytes().expect("receipt canonicalizes");
    validate_schema_test_receipt_for_package(&receipt_bytes, &fixture.package.prepared, &suite)
        .expect("asset action receipt revalidates against the exact prepared package");
    assert_eq!(
        receipt.successful_journey_ids(),
        ["create-asset-and-initial-inspection"]
    );

    assert_asset_registration_rows(&fixture.database, &fixture.registry).await;
    assert_immediate_action_success_bodies(
        &fixture.database,
        "register-asset-with-inspection",
        &[&["asset"]],
    )
    .await;
    assert_response_body_omits(
        &fixture.database,
        &[
            "initial-inspection",
            "observedAt",
            "initialResult",
            "Synthetic generator",
        ],
    )
    .await;

    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn household_contact_action_example_runs_patch_conditions_and_replay_without_data_loss() {
    let fixture = RunningFixture::start("household-contact-actions").await;
    assert_action_profile_has_no_crud_route(&fixture.registry, "contact-registrar");

    let suite = validate_fixture_journeys(&fixture.sources.journeys, &fixture.registry)
        .unwrap_or_else(|error| {
            panic!(
                "household action journeys preflight against the Production registry: {}",
                fixture_error_with_source_context(&fixture.sources.journeys, &error)
            )
        });
    let runner = prepare_runner(
        &fixture.package,
        &fixture.sources,
        &suite,
        &fixture.prepared,
        household_contact_tokens(&fixture.sources.journeys, &suite, &fixture.idp),
    )
    .await;
    let completed = runner.run_all().await.unwrap_or_else(|error| {
        panic!(
            "household action journeys execute through the authenticated PostgreSQL router: {}",
            fixture_error_with_source_context(&fixture.sources.journeys, &error)
        )
    });
    let receipt = completed
        .build_receipt(&suite)
        .expect("household action execution emits a bound schema-test receipt");
    let receipt_bytes = receipt.canonical_bytes().expect("receipt canonicalizes");
    validate_schema_test_receipt_for_package(&receipt_bytes, &fixture.package.prepared, &suite)
        .expect("household action receipt revalidates against the exact prepared package");
    assert_eq!(
        receipt.successful_journey_ids(),
        [
            "action-only-household-contact-registration",
            "link-only-target-authority-is-still-enforced"
        ]
    );

    assert_household_contact_rows(&fixture.database, &fixture.registry).await;
    assert_immediate_action_success_bodies(
        &fixture.database,
        "register-household-contact",
        &[&["household", "membership", "person"]],
    )
    .await;
    assert_response_body_omits(
        &fixture.database,
        &[
            "contactName",
            "personCode",
            "Alicia Rivera",
            "PERSON-ACTION-001",
            "serviceCenterId",
        ],
    )
    .await;

    fixture.finish().await;
}

struct RunningFixture {
    database: TestDatabase,
    registry: Arc<CompiledRegistry>,
    prepared: PreparedServer,
    idp: MockIdp,
    package: TestPackage,
    sources: ExampleSources,
}

impl RunningFixture {
    async fn start(name: &str) -> Self {
        let sources = ExampleSources::load(name);
        let registry = Arc::new(sources.compiled.clone());
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("administrator installs the compiler-owned action example schema");
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("managed schema fingerprint computes for action example");
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
        .expect("database initializes from the exact signed action example identity");
        drop(migration);
        migration_task.abort();

        let idp = MockIdp::start().await;
        let config_path = package.write_runtime_config(&database, &idp);
        let prepared =
            prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
                .await
                .expect("verified startup constructs the authenticated action example runtime");

        Self {
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
        }
    }

    async fn finish(self) {
        let Self {
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
        } = self;
        drop(prepared);
        drop(registry);
        drop(package);
        drop(sources);
        idp.stop().await;
        database.cleanup().await;
    }
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
            .join("../../products/registry-server/fixtures")
            .join(name);
        let project_bytes = fs::read(root.join("registry.yaml"))
            .expect("action example registry source is readable");
        let project = parse_project_yaml(&project_bytes)
            .expect("action example registry follows the strict authoring contract");
        let mut modules = Vec::new();
        let mut parsed_modules = Vec::new();
        for locked in &project.modules {
            let path = format!("modules/{}/module.yaml", locked.id);
            let bytes = fs::read(root.join(&path))
                .expect("locked action example module source is readable");
            let module = parse_module_yaml(&bytes)
                .expect("locked action example module follows the strict authoring contract");
            modules.push(ExampleModule {
                id: locked.id.clone(),
                path,
                bytes,
            });
            parsed_modules.push(module);
        }
        let compiled =
            compile_project_with_assets(&project, &parsed_modules, &[], CompileProfile::Production)
                .expect("action example closes under the Production compiler");
        let journeys = fs::read(root.join("tests/journeys.yaml"))
            .expect("action example journeys are readable");
        Self {
            project,
            project_bytes,
            modules,
            journeys,
            compiled,
        }
    }
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
            .expect("action example declares package identity");
        let database_id = format!("{}-database", sources.project.registry.id);
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("action example package signing key generates");
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
        .expect("action example package prepares from exact sources");
        let migration_plan = prepared
            .file_bytes()
            .get("database/migration-plan.json")
            .expect("prepared action example package includes migration plan")
            .clone();
        let root = tempfile::tempdir().expect("temporary action example package root creates");
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
            .expect("signed action example package publishes");
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
        .expect("published action example package rederives and verifies");
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

    fn write_runtime_config(&self, database: &TestDatabase, idp: &MockIdp) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("action example secret root creates");
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
        let path = self.directory.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:9
  trustedProxy: direct
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
        .expect("strict action example runtime configuration writes");
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
            "action example runner derives exact package and same-database facts: {}",
            fixture_error_with_source_context(&sources.journeys, &error)
        )
    })
}

fn assert_action_profile_has_no_crud_route(registry: &CompiledRegistry, profile_id: &str) {
    assert!(
        registry
            .routes()
            .routes
            .iter()
            .all(|route| !route.access_profiles.iter().any(|id| id == profile_id)),
        "immediate-action profile must not receive ordinary entity CRUD routes"
    );
    assert!(
        registry
            .actions()
            .routes
            .iter()
            .any(|route| route.access_profiles.iter().any(|id| id == profile_id)),
        "immediate-action profile must be visible only through compiled action routes"
    );
}

fn asset_registration_tokens(
    journey_source: &[u8],
    suite: &ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> Vec<String> {
    tokens_for_source_steps(
        journey_source,
        suite,
        [
            (
                "create-asset-and-initial-inspection",
                "invoke-registration-action",
                action_token(
                    idp,
                    "synthetic-asset-registrar",
                    "asset-registration",
                    &[("jurisdiction", "north-district")],
                    &["registry:asset:register"],
                ),
            ),
            (
                "create-asset-and-initial-inspection",
                "retry-lost-registration-response",
                action_token(
                    idp,
                    "synthetic-asset-registrar",
                    "asset-registration",
                    &[("jurisdiction", "north-district")],
                    &["registry:asset:register"],
                ),
            ),
            (
                "create-asset-and-initial-inspection",
                "reused-key-with-different-body-is-refused",
                action_token(
                    idp,
                    "synthetic-asset-registrar",
                    "asset-registration",
                    &[("jurisdiction", "north-district")],
                    &["registry:asset:register"],
                ),
            ),
            (
                "create-asset-and-initial-inspection",
                "boundary-escape-is-refused",
                action_token(
                    idp,
                    "synthetic-asset-registrar",
                    "asset-registration",
                    &[("jurisdiction", "north-district")],
                    &["registry:asset:register"],
                ),
            ),
        ],
    )
}

fn household_contact_tokens(
    journey_source: &[u8],
    suite: &ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> Vec<String> {
    tokens_for_source_steps(
        journey_source,
        suite,
        [
            (
                "action-only-household-contact-registration",
                "create-household",
                action_token(
                    idp,
                    "synthetic-household-operator",
                    "household-administration",
                    &[("district", "north-district")],
                    &["registry:household:operate"],
                ),
            ),
            (
                "action-only-household-contact-registration",
                "create-service-center",
                action_token(
                    idp,
                    "synthetic-household-operator",
                    "household-administration",
                    &[("district", "north-district")],
                    &["registry:household:operate"],
                ),
            ),
            (
                "action-only-household-contact-registration",
                "read-household-action-condition",
                contact_registrar_token(idp),
            ),
            (
                "action-only-household-contact-registration",
                "read-household-for-maintenance",
                action_token(
                    idp,
                    "synthetic-household-maintainer",
                    "household-maintenance",
                    &[("district", "north-district")],
                    &["registry:household:maintain"],
                ),
            ),
            (
                "action-only-household-contact-registration",
                "stale-household-after-user-selection",
                action_token(
                    idp,
                    "synthetic-household-maintainer",
                    "household-maintenance",
                    &[("district", "north-district")],
                    &["registry:household:maintain"],
                ),
            ),
            (
                "action-only-household-contact-registration",
                "stale-condition-refuses-without-dropping-input",
                contact_registrar_token(idp),
            ),
            (
                "action-only-household-contact-registration",
                "refresh-household-action-condition",
                contact_registrar_token(idp),
            ),
            (
                "action-only-household-contact-registration",
                "invoke-contact-registration-action",
                contact_registrar_token(idp),
            ),
            (
                "action-only-household-contact-registration",
                "retry-lost-contact-registration-response",
                contact_registrar_token(idp),
            ),
            (
                "action-only-household-contact-registration",
                "same-key-different-input-is-refused",
                contact_registrar_token(idp),
            ),
            (
                "link-only-target-authority-is-still-enforced",
                "create-household",
                action_token(
                    idp,
                    "synthetic-household-operator",
                    "household-administration",
                    &[("district", "north-district")],
                    &["registry:household:operate"],
                ),
            ),
            (
                "link-only-target-authority-is-still-enforced",
                "create-south-service-center",
                action_token(
                    idp,
                    "synthetic-household-operator",
                    "household-administration",
                    &[("district", "south-district")],
                    &["registry:household:operate"],
                ),
            ),
            (
                "link-only-target-authority-is-still-enforced",
                "read-north-household-condition",
                contact_registrar_token(idp),
            ),
            (
                "link-only-target-authority-is-still-enforced",
                "link-only-service-center-outside-boundary-is-concealed",
                contact_registrar_token(idp),
            ),
        ],
    )
}

fn contact_registrar_token(idp: &MockIdp) -> String {
    action_token(
        idp,
        "synthetic-contact-registrar",
        "contact-registration",
        &[("district", "north-district")],
        &["registry:contact:register"],
    )
}

fn tokens_for_source_steps<const N: usize>(
    journey_source: &[u8],
    suite: &ValidatedFixtureJourneys,
    tokens: [(&'static str, &'static str, String); N],
) -> Vec<String> {
    let mut expected = tokens
        .into_iter()
        .map(|(journey, step, token)| ((journey.to_owned(), step.to_owned()), token))
        .collect::<std::collections::BTreeMap<_, _>>();
    let journeys = source_journey_steps(journey_source);
    assert_eq!(
        journeys
            .iter()
            .map(|journey| journey.id.as_str())
            .collect::<Vec<_>>(),
        suite.journey_ids(),
        "source and validated journey order must match before assigning bearer tokens"
    );
    let mut ordered = Vec::new();
    for journey in &journeys {
        for step in &journey.steps {
            let token = expected
                .remove(&(journey.id.clone(), step.clone()))
                .unwrap_or_else(|| {
                    panic!(
                        "validated action example step {}.{} has a MockIdp token",
                        journey.id, step
                    )
                });
            ordered.push(token);
        }
    }
    assert!(
        expected.is_empty(),
        "MockIdp token list must not include stale action example steps"
    );
    ordered
}

#[derive(Debug)]
struct SourceJourneySteps {
    id: String,
    steps: Vec<String>,
}

fn source_journey_steps(bytes: &[u8]) -> Vec<SourceJourneySteps> {
    let text = std::str::from_utf8(bytes).expect("journey source is UTF-8");
    let mut journeys = Vec::new();
    let mut current: Option<SourceJourneySteps> = None;
    let mut in_journeys = false;
    let mut in_steps = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line == "journeys:" {
            in_journeys = true;
            continue;
        }
        if !in_journeys {
            continue;
        }
        if let Some(id) = line.strip_prefix("  - id: ") {
            if let Some(journey) = current.take() {
                journeys.push(journey);
            }
            current = Some(SourceJourneySteps {
                id: plain_yaml_scalar(id),
                steps: Vec::new(),
            });
            in_steps = false;
            continue;
        }
        if line == "    steps:" {
            in_steps = true;
            continue;
        }
        if in_steps {
            if let Some(id) = line.strip_prefix("      - id: ") {
                current
                    .as_mut()
                    .expect("step appears under a source journey")
                    .steps
                    .push(plain_yaml_scalar(id));
            }
        }
    }
    if let Some(journey) = current {
        journeys.push(journey);
    }
    assert!(
        !journeys.is_empty() && journeys.iter().all(|journey| !journey.steps.is_empty()),
        "action example journey source must contain ordered journeys and steps"
    );
    journeys
}

fn plain_yaml_scalar(value: &str) -> String {
    let value = value
        .split_once(" #")
        .map_or(value, |(head, _)| head)
        .trim();
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
        .to_owned()
}

fn fixture_error_with_source_context(journey_source: &[u8], error: &FixtureError) -> String {
    if let FixtureError::StepFailed {
        journey_index,
        step_index,
        ..
    } = error
    {
        let journeys = source_journey_steps(journey_source);
        if let Some(journey) = journeys.get(*journey_index) {
            if let Some(step) = journey.steps.get(*step_index) {
                return format!("{}.{}: {error}", journey.id, step);
            }
        }
    }
    error.to_string()
}

fn action_token(
    idp: &MockIdp,
    principal: &str,
    purpose: &str,
    boundary_claims: &[(&str, &str)],
    scopes: &[&str],
) -> String {
    let mut claims = json!({
        "aud": AUDIENCE,
        "registry_principal": principal,
        "purpose": purpose,
    });
    if !scopes.is_empty() {
        claims["scope"] = Value::String(scopes.join(" "));
    }
    for (name, value) in boundary_claims {
        claims[*name] = Value::String((*value).to_owned());
    }
    idp.mint_token(claims)
}

async fn assert_asset_registration_rows(database: &TestDatabase, registry: &CompiledRegistry) {
    let asset = entity_sql(registry, "asset");
    let inspection = entity_sql(registry, "asset-inspection");
    let asset_rows = database
        .admin
        .query(
            &format!(
                "SELECT {asset_code}, {label}, {asset_type}, {jurisdiction}, record_revision
                   FROM registry_data.{asset_table}
                  ORDER BY {asset_code}",
                asset_code = q(&asset.field("asset-code")),
                label = q(&asset.field("label")),
                asset_type = q(&asset.field("asset-type")),
                jurisdiction = q(&asset.field("jurisdiction")),
                asset_table = q(&asset.table),
            ),
            &[],
        )
        .await
        .expect("administrator inspects exact asset rows");
    assert_eq!(asset_rows.len(), 1);
    assert_eq!(asset_rows[0].get::<_, String>(0), "ASSET-ACTION-001");
    assert_eq!(asset_rows[0].get::<_, String>(1), "Synthetic generator");
    assert_eq!(asset_rows[0].get::<_, String>(2), "equipment");
    assert_eq!(asset_rows[0].get::<_, String>(3), "north-district");
    assert_eq!(asset_rows[0].get::<_, i64>(4), 1);

    let inspection_count = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_data.{inspection_table}
                  WHERE {jurisdiction} = 'north-district'",
                inspection_table = q(&inspection.table),
                jurisdiction = q(&inspection.field("jurisdiction")),
            ),
            &[],
        )
        .await
        .expect("administrator counts committed inspection rows")
        .get::<_, i64>(0);
    assert_eq!(inspection_count, 1);

    let south_count = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_data.{asset_table}
                  WHERE {jurisdiction} = 'south-district'",
                asset_table = q(&asset.table),
                jurisdiction = q(&asset.field("jurisdiction")),
            ),
            &[],
        )
        .await
        .expect("administrator counts refused boundary escape rows")
        .get::<_, i64>(0);
    assert_eq!(south_count, 0);
}

async fn assert_household_contact_rows(database: &TestDatabase, registry: &CompiledRegistry) {
    let household = entity_sql(registry, "household");
    let person = entity_sql(registry, "person");
    let membership = entity_sql(registry, "group-membership");
    let household_rows = database
        .admin
        .query(
            &format!(
                "SELECT {household_code}, {household_name}, {district}, {contact_person}::text,
                        record_revision
                   FROM registry_data.{household_table}
                  ORDER BY {household_code}",
                household_code = q(&household.field("household-code")),
                household_name = q(&household.field("household-name")),
                district = q(&household.field("district")),
                contact_person = q(&household.field("contact-person")),
                household_table = q(&household.table),
            ),
            &[],
        )
        .await
        .expect("administrator inspects household rows after action journey");
    assert_eq!(household_rows.len(), 2);
    assert_eq!(household_rows[0].get::<_, String>(0), "HH-ACTION-001");
    assert_eq!(
        household_rows[0].get::<_, String>(1),
        "Rivera family household"
    );
    assert_eq!(household_rows[0].get::<_, String>(2), "north-district");
    assert!(
        household_rows[0].get::<_, Option<String>>(3).is_some(),
        "successful action patches the selected household contact"
    );
    assert_eq!(household_rows[0].get::<_, i64>(4), 3);
    assert_eq!(household_rows[1].get::<_, String>(0), "HH-ACTION-002");
    assert_eq!(household_rows[1].get::<_, Option<String>>(3), None);

    let people = database
        .admin
        .query(
            &format!(
                "SELECT {person_code}, {legal_name}, {district}
                   FROM registry_data.{person_table}
                  ORDER BY {person_code}",
                person_code = q(&person.field("person-code")),
                legal_name = q(&person.field("legal-name")),
                district = q(&person.field("district")),
                person_table = q(&person.table),
            ),
            &[],
        )
        .await
        .expect("administrator inspects exact person rows");
    assert_eq!(people.len(), 1);
    assert_eq!(people[0].get::<_, String>(0), "PERSON-ACTION-001");
    assert_eq!(people[0].get::<_, String>(1), "Alicia Rivera");
    assert_eq!(people[0].get::<_, String>(2), "north-district");

    let membership_count = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_data.{membership_table}
                  WHERE {district} = 'north-district'",
                membership_table = q(&membership.table),
                district = q(&membership.field("district")),
            ),
            &[],
        )
        .await
        .expect("administrator counts committed membership rows")
        .get::<_, i64>(0);
    assert_eq!(membership_count, 1);
}

async fn assert_immediate_action_success_bodies(
    database: &TestDatabase,
    action_id: &str,
    expected_result_sets: &[&[&str]],
) {
    let rows = database
        .admin
        .query(
            "SELECT response_body
               FROM registry_internal.registry_idempotency
              WHERE result_kind = 'immediate_action'
                AND response_status = 200
              ORDER BY key_reference",
            &[],
        )
        .await
        .expect("administrator inspects stored immediate-action receipts");
    assert_eq!(rows.len(), expected_result_sets.len());
    for (row, expected_results) in rows.iter().zip(expected_result_sets) {
        let bytes: Vec<u8> = row.get(0);
        let body: Value = serde_json::from_slice(&bytes).expect("stored response is JSON");
        assert_eq!(body.get("action").and_then(Value::as_str), Some(action_id));
        let results = body
            .get("results")
            .and_then(Value::as_object)
            .expect("action response stores result references");
        assert_eq!(
            results.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_results.iter().copied().collect::<BTreeSet<_>>()
        );
        for result in results.values() {
            assert!(result.get("id").and_then(Value::as_str).is_some());
            assert!(result.get("entity").and_then(Value::as_str).is_some());
            assert!(result.get("revision").and_then(Value::as_u64).is_some());
            assert_eq!(result.as_object().expect("result is object").len(), 3);
        }
    }
}

async fn assert_response_body_omits(database: &TestDatabase, forbidden: &[&str]) {
    let rows = database
        .admin
        .query(
            "SELECT response_body
               FROM registry_internal.registry_idempotency
              WHERE result_kind = 'immediate_action'
                AND response_body IS NOT NULL",
            &[],
        )
        .await
        .expect("administrator inspects stored immediate-action responses");
    let mut text = String::new();
    for row in rows {
        let bytes: Vec<u8> = row.get(0);
        text.push_str(
            std::str::from_utf8(&bytes).expect("stored immediate-action response is UTF-8 JSON"),
        );
    }
    for value in forbidden {
        assert!(
            !text.contains(value),
            "immediate action stored response leaked {value}"
        );
    }
}

struct EntitySql {
    table: String,
    fields: std::collections::BTreeMap<String, String>,
}

impl EntitySql {
    fn field(&self, id: &str) -> String {
        self.fields
            .get(id)
            .unwrap_or_else(|| panic!("compiled entity has field {id}"))
            .clone()
    }
}

fn entity_sql(registry: &CompiledRegistry, entity_id: &str) -> EntitySql {
    let names = registry
        .physical_names()
        .entities
        .get(entity_id)
        .unwrap_or_else(|| panic!("compiled registry has entity {entity_id}"));
    EntitySql {
        table: names.table.clone(),
        fields: names.fields.clone(),
    }
}

fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private action example file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private action example file permissions set");
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
