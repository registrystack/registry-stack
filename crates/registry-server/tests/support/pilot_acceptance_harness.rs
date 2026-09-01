// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderName, HeaderValue, Method, Request, Response};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::MockIdp;
use registry_server::compiler::{compile_project_with_assets, CompileProfile};
use registry_server::contract::{
    parse_module_yaml, parse_project_yaml, ModuleAssetSource, Operation, RegistryProject,
};
use registry_server::package::{
    load_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, SignaturePolicy, TrustAnchorKey, TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_server::startup::{prepare_with_connection_and_key_source_for_test, PreparedServer};
use registry_server::CompiledRegistry;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

use super::postgres_harness::TestDatabase;

const AUDIENCE: &str = "urn:registry-server:pilot-acceptance";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct PilotHarness {
    pub database: TestDatabase,
    pub registry: Arc<CompiledRegistry>,
    prepared: PreparedServer,
    idp: MockIdp,
    scratch: ScratchDirectory,
}

/// A real loopback listener serving the exact Router assembled by startup.
///
/// This test-only seam lets client journeys exercise the deployed HTTP
/// boundary without introducing another way to construct server state.
pub struct PilotHttpServer {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl PilotHttpServer {
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn finish(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("pilot HTTP listener task joins");
        }
    }
}

impl Drop for PilotHttpServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl PilotHarness {
    pub async fn start(fixture_name: &str) -> Self {
        let sources = FixtureSources::load(fixture_name);
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("Production pilot fixture declares package identity")
            .clone();
        let database_id = format!("{}-acceptance-db", sources.project.registry.id);
        let database = TestDatabase::create(8).await;
        database
            .admin
            .batch_execute(&format!(
                "ALTER ROLE \"{}\" SET timezone TO 'Asia/Bangkok';",
                database.runtime_role.as_str()
            ))
            .await
            .expect("pilot runtime role explicitly uses a non-UTC session timezone");
        let timezone_probe_pool = database
            .runtime_config
            .build_pool()
            .expect("timezone probe pool builds from the exact runtime role");
        let timezone_probe = timezone_probe_pool
            .get_for_test()
            .await
            .expect("timezone probe opens a runtime-role session");
        let timezone: String = timezone_probe
            .query_one("SHOW timezone", &[])
            .await
            .expect("runtime session exposes its configured timezone")
            .get(0);
        assert_eq!(timezone, "Asia/Bangkok");
        drop(timezone_probe);
        drop(timezone_probe_pool);
        if sources.compiled.ddl().requires_btree_gist {
            database
                .admin
                .execute("CREATE EXTENSION IF NOT EXISTS btree_gist", &[])
                .await
                .expect("administrator installs the generic temporal exclusion dependency");
        }
        let (migration, migration_task) = database.connect_migration().await;
        let scratch = ScratchDirectory::new(fixture_name);
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("pilot package signing key generates");

        let provisional = PublishedPackage::build(
            scratch.path(),
            "provisional",
            &sources,
            &database_id,
            fingerprint(1),
            &signing,
        );
        let provisional_context =
            provisional.context(&identity, &database_id, PackageIntent::InitialActivation);
        let verified_provisional = load_package(&provisional.root, &provisional_context)
            .expect("exact committed pilot sources prepare a closed Production package");
        assert_eq!(verified_provisional.registry(), &sources.compiled);
        install_compiled_schema(
            &migration,
            verified_provisional.registry(),
            &database.runtime_role,
        )
        .await
        .expect("pilot Production schema installs without in-memory repair");
        let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("installed pilot schema has an exact managed fingerprint");
        drop(verified_provisional);

        let package = PublishedPackage::build(
            scratch.path(),
            "active",
            &sources,
            &database_id,
            schema_fingerprint,
            &signing,
        );
        let package_context =
            package.context(&identity, &database_id, PackageIntent::InitialActivation);
        let verified = load_package(&package.root, &package_context)
            .expect("signed pilot package verifies with its exact committed sources");
        assert_eq!(verified.registry(), &sources.compiled);
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            verified.registry(),
            RegistryStateTestIdentity {
                package_id: &verified.manifest().package_id,
                environment: &verified.manifest().environment,
                instance_id: &verified.manifest().instance_id,
                database_id: &verified.manifest().database_id,
                package_revision: &verified.manifest().package_revision,
                package_sequence: i64::try_from(verified.manifest().sequence)
                    .expect("pilot package sequence fits PostgreSQL"),
            },
        )
        .await
        .expect("database initializes from the exact signed pilot identity");
        drop(verified);
        drop(migration);
        migration_task.abort();

        let idp = MockIdp::start().await;
        let config_path = write_runtime_config(
            scratch.path(),
            &package,
            &identity,
            &database_id,
            &database,
            &idp,
            &sources.compiled,
        );
        let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig {
                cache_ttl: Duration::from_secs(60),
                negative_cache_ttl: Duration::from_secs(1),
                refresh_cooldown: Duration::from_secs(1),
                max_doc_bytes: 64 * 1024,
                request_timeout: Duration::from_secs(5),
                outage_tolerance: Duration::ZERO,
            },
            FetchUrlPolicy::dev(),
        ));
        let prepared = prepare_with_connection_and_key_source_for_test(
            &config_path,
            database.runtime_config.clone(),
            key_source,
        )
        .await
        .expect("existing startup seam accepts the exact package, database, audit, and MockIdp");

        Self {
            database,
            registry: Arc::new(sources.compiled),
            prepared,
            idp,
            scratch,
        }
    }

    pub fn token(&self, purpose: &str, row_boundary_claims: &[(&str, Value)]) -> String {
        self.token_with_scopes(purpose, row_boundary_claims, &[])
    }

    pub fn token_with_scopes(
        &self,
        purpose: &str,
        row_boundary_claims: &[(&str, Value)],
        scopes: &[&str],
    ) -> String {
        let mut claims = json!({
            "aud": AUDIENCE,
            "registry_principal": "pilot-operator",
            "purpose": purpose,
        });
        if !scopes.is_empty() {
            claims["scope"] = Value::String(scopes.join(" "));
        }
        for (name, value) in row_boundary_claims {
            claims[*name] = value.clone();
        }
        self.idp.mint_token(claims)
    }

    pub async fn send(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Response<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body))
            .expect("pilot HTTP request builds");
        if let Some(token) = token {
            request.headers_mut().insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .expect("MockIdp bearer value is valid"),
            );
        }
        for (name, value) in headers {
            request.headers_mut().append(
                HeaderName::from_bytes(name.as_bytes()).expect("pilot header name is valid"),
                HeaderValue::from_str(value).expect("pilot header value is valid"),
            );
        }
        self.prepared
            .app()
            .oneshot(request)
            .await
            .expect("PreparedServer router responds")
    }

    pub async fn send_json(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        idempotency_key: Option<&str>,
        body: Value,
    ) -> Response<Body> {
        let mut headers = vec![("content-type", "application/json")];
        if let Some(key) = idempotency_key {
            headers.push(("idempotency-key", key));
        }
        self.send(
            method,
            uri,
            token,
            &headers,
            serde_json::to_vec(&body).expect("pilot request JSON serializes"),
        )
        .await
    }

    /// Serve the verified startup Router on an ephemeral loopback listener.
    pub async fn serve_http(&self) -> PilotHttpServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("pilot HTTP listener binds on loopback");
        let address = listener
            .local_addr()
            .expect("pilot listener has an address");
        let app = self.prepared.app();
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("pilot HTTP listener serves the verified Router");
        });
        PilotHttpServer {
            base_url: format!("http://{address}"),
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub async fn finish(self) {
        let Self {
            database,
            registry,
            prepared,
            idp,
            scratch,
        } = self;
        drop(prepared);
        drop(registry);
        idp.stop().await;
        database.cleanup().await;
        drop(scratch);
    }
}

pub async fn response_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("bounded pilot response body reads")
        .to_vec()
}

pub async fn response_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&response_bytes(response).await).expect("pilot response is strict JSON")
}

struct FixtureSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    modules: Vec<(String, Vec<u8>)>,
    module_assets: Vec<ModuleAssetSource>,
    compiled: CompiledRegistry,
}

impl FixtureSources {
    fn load(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/registry-server/acceptance")
            .join(name);
        let project_bytes = fs::read(root.join("registry.yaml"))
            .expect("committed pilot registry source is readable");
        let project = parse_project_yaml(&project_bytes)
            .expect("committed pilot registry follows the strict authoring contract");
        let mut modules = Vec::new();
        let mut parsed_modules = Vec::new();
        let mut module_assets = Vec::new();
        for locked in &project.modules {
            let module_root = root.join("modules").join(&locked.id);
            let bytes = fs::read(module_root.join("module.yaml"))
                .expect("every exact locked module source is committed and readable");
            let module = parse_module_yaml(&bytes)
                .expect("committed pilot module follows the strict contract");
            let declared_assets = module
                .entities
                .iter()
                .flat_map(|entity| &entity.derived)
                .chain(
                    module
                        .extend_entities
                        .iter()
                        .flat_map(|extension| &extension.derived),
                )
                .map(|derived| derived.sql.clone())
                .collect::<BTreeSet<_>>();
            for asset_path in declared_assets {
                module_assets.push(ModuleAssetSource {
                    module: Some(module.id.clone()),
                    bytes: fs::read(module_root.join(&asset_path))
                        .expect("every declared module SQL asset is committed and readable"),
                    path: asset_path,
                });
            }
            modules.push((locked.id.clone(), bytes));
            parsed_modules.push(module);
        }
        let compiled = compile_project_with_assets(
            &project,
            &parsed_modules,
            &module_assets,
            CompileProfile::Production,
        )
        .expect("pilot fixture closes under the Production compiler without repair");
        Self {
            project,
            project_bytes,
            modules,
            module_assets,
            compiled,
        }
    }
}

struct PublishedPackage {
    root: PathBuf,
    anchor: PathBuf,
    revision: String,
}

impl PublishedPackage {
    fn build(
        parent: &Path,
        label: &str,
        sources: &FixtureSources,
        database_id: &str,
        schema_fingerprint: String,
        signing: &PrivateJwk,
    ) -> Self {
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("Production pilot identity exists");
        let key_id = signing.public().kid.expect("generated signing key has kid");
        let prepared = registry_server::package::prepare_package(PackageBuildRequest {
            environment: identity.environment.clone(),
            instance_id: identity.instance_id.clone(),
            database_id: database_id.to_owned(),
            sequence: identity.sequence,
            prior_revision: None,
            compiler_source_revision: identity.source_revision.clone(),
            schema_fingerprint,
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: sources.project_bytes.clone(),
            },
            modules: sources
                .modules
                .iter()
                .map(|(id, bytes)| PackageModuleSource {
                    id: id.clone(),
                    path: format!("source/modules/{id}/module.yaml"),
                    bytes: bytes.clone(),
                    assets: sources
                        .module_assets
                        .iter()
                        .filter(|asset| asset.module.as_deref() == Some(id.as_str()))
                        .map(|asset| PackageSourceFile {
                            path: asset.path.clone(),
                            bytes: asset.bytes.clone(),
                        })
                        .collect(),
                })
                .collect(),
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: fixture_journey_bytes(&sources.compiled),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("exact pilot sources prepare as a Production package");
        let signature = sign(prepared.canonical_signed_bytes(), signing)
            .expect("pilot package signature succeeds");
        let root = parent.join(format!("package-{label}"));
        prepared
            .publish_to_directory(
                &root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("signed pilot package publishes to a closed directory");
        let anchor = parent.join(format!("trust-anchor-{label}.json"));
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: identity.environment.clone(),
                instance_id: identity.instance_id.clone(),
                database_id: database_id.to_owned(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public())
                        .expect("pilot public JWK serializes"),
                }],
            },
        );
        Self {
            root,
            anchor,
            revision: prepared.package_revision().to_owned(),
        }
    }

    fn context<'a>(
        &'a self,
        identity: &'a registry_server::contract::PackageIdentitySource,
        database_id: &'a str,
        intent: PackageIntent<'a>,
    ) -> PackageLoadContext<'a> {
        PackageLoadContext {
            environment: &identity.environment,
            instance_id: &identity.instance_id,
            database_id,
            database_initialization_environment: &identity.environment,
            compiler_source_revision: &identity.source_revision,
            trust_anchor: Some(&self.anchor),
            intent,
        }
    }
}

fn fixture_journey_bytes(registry: &CompiledRegistry) -> Vec<u8> {
    let (entity_id, profile_id, profile) = registry
        .entities()
        .iter()
        .flat_map(|(entity_id, entity)| {
            entity
                .access_profiles
                .iter()
                .map(move |(profile_id, profile)| (entity_id, profile_id, profile))
        })
        .find(|(_, _, profile)| profile.operations.contains(&Operation::List))
        .expect("every pilot fixture exposes one configured list journey");
    let claims = if profile.anonymous {
        json!({})
    } else {
        let direct_claims = profile
            .row_boundaries
            .iter()
            .map(|boundary| {
                (
                    boundary.claim.clone(),
                    Value::String("fixture-boundary".to_owned()),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let mut claims = serde_json::Map::new();
        claims.insert(
            "principal".to_owned(),
            Value::String("fixture-operator".to_owned()),
        );
        if !profile.required_scopes.is_empty() {
            claims.insert(
                "scopes".to_owned(),
                Value::Array(
                    profile
                        .required_scopes
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        if let Some(purpose) = profile.required_purposes.iter().next() {
            claims.insert("purpose".to_owned(), Value::String(purpose.clone()));
        }
        if !direct_claims.is_empty() {
            claims.insert("directClaims".to_owned(), Value::Object(direct_claims));
        }
        Value::Object(claims)
    };
    serde_norway::to_string(&json!({
        "apiVersion": "registry.registrystack.org/server-journeys/v1",
        "journeys": [{
            "id": "pilot-package-list",
            "steps": [{
                "id": "list-configured-records",
                "entity": entity_id,
                "accessProfile": profile_id,
                "claims": claims,
                "request": {"operation": "list"},
                "expect": {"outcome": "success", "status": 200, "count": 0}
            }]
        }]
    }))
    .expect("generated pilot fixture journey serializes")
    .into_bytes()
}

fn write_runtime_config(
    root: &Path,
    package: &PublishedPackage,
    identity: &registry_server::contract::PackageIdentitySource,
    database_id: &str,
    database: &TestDatabase,
    idp: &MockIdp,
    _registry: &CompiledRegistry,
) -> PathBuf {
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).expect("pilot secret root creates");
    write_secret(
        &secrets.join("database-url"),
        b"unused-by-test-startup-seam",
    );
    write_secret(&secrets.join("audit-key"), &[0x6b; 32]);
    write_secret(&secrets.join("cursor-key"), &[0x43; 32]);
    let path = root.join("runtime.yaml");
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
  databaseId: {database_id}
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
            identity.environment,
            secrets.display(),
            database.migration_role.as_str(),
            database.runtime_role.as_str(),
            package.root.display(),
            package.anchor.display(),
            identity.source_revision,
            package.revision,
            identity.sequence,
            idp.issuer(),
        ),
    )
    .expect("strict pilot runtime configuration writes");
    set_private_permissions(&path);
    path
}

fn write_secret(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("pilot secret writes");
    set_private_permissions(path);
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    fs::write(path, bytes).expect("pilot trust anchor writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("pilot private file permissions set");
    }
}

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new(label: &str) -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_nanos();
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "registry-server-pilot-{}-{label}-{nanos}-{ordinal}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("pilot scratch directory creates");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String succeeds");
    }
    result
}
