// SPDX-License-Identifier: Apache-2.0
//! Immutable package loading and explicit PostgreSQL activation.
use crate::{
    access::AccessConfig,
    definition::{Definition, MAX_SNAPSHOT_BYTES},
    protected_state::StateKeys,
    runtime::RuntimeConfig,
    store::{Store, StoreSecurity, AUDIT_SCHEMA},
    CoordinatorError, Result,
};
use registry_platform_activation::{self as activation, Layout, NewActivation, RoleMode};
use registry_platform_audit::{AuditDestination, AuditProfile, AuditWriter, FileDestination};
use registry_platform_config::{
    package::{write_package, PackageLimits},
    DatabaseConfig, ListenerConfig, PackageConfig, PrivateListenerConfig, SecretProvidersConfig,
    SecretReference, TlsTermination,
};
use registry_platform_yaml::{Diagnostic, Document, Source};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentConfig {
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::ExternalId", extend("maxLength" = 128)))]
    pub database_id: String,
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^[a-z_][a-z0-9_]{0,62}$", "maxLength" = 63)))]
    pub runtime_role: String,
    /// One pinned package per flow; the flow is the package's workflow id.
    pub packages: Vec<PackageConfig>,
    pub listener: PrivateListenerConfig,
    /// The operator-private socket `/metrics` is served on. When it is
    /// omitted, no metrics are served.
    #[serde(default)]
    pub metrics_listener: Option<ListenerConfig>,
    pub authentication: AccessConfig,
    #[serde(rename = "auditFile")]
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN)))]
    pub audit_path: PathBuf,
    pub audit_key_ref: SecretReference,
    #[serde(deserialize_with = "crate::runtime::key_version")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, {u32::MAX}>")
    )]
    pub active_state_key: u32,
    #[cfg_attr(
        feature = "schema",
        schemars(extend(
            "minProperties" = 1,
            "maxProperties" = 16,
            "propertyNames" = {"$ref": "#/$defs/ExternalId", "pattern": "^[1-9][0-9]*$", "maxLength": 10}
        ))
    )]
    #[serde(with = "state_key_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, StateKeyConfig>")
    )]
    pub state_keys: BTreeMap<String, SecretReference>,
    pub admission_key_ref: SecretReference,
}
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateKeyConfig {
    key_ref: SecretReference,
}
mod state_key_map {
    use super::*;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<String, SecretReference>, D::Error> {
        BTreeMap::<registry_platform_yaml::ExternalId, StateKeyConfig>::deserialize(deserializer)
            .map(|keys| {
                keys.into_iter()
                    .map(|(version, key)| (version.into_string(), key.key_ref))
                    .collect()
            })
    }
    pub fn serialize<S: serde::Serializer>(
        keys: &BTreeMap<String, SecretReference>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let wire: BTreeMap<_, _> = keys
            .iter()
            .map(|(version, key_ref)| {
                (
                    version,
                    StateKeyConfig {
                        key_ref: key_ref.clone(),
                    },
                )
            })
            .collect();
        wire.serialize(serializer)
    }
}
impl DeploymentConfig {
    pub fn local(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }
    pub fn validate(&self, secrets: &SecretProvidersConfig) -> Result<()> {
        self.findings(secrets)
            .into_iter()
            .next()
            .map_or(Ok(()), Err)
    }
    pub(crate) fn findings(&self, secrets: &SecretProvidersConfig) -> Vec<CoordinatorError> {
        let mut errors = Vec::new();
        if self.packages.is_empty() || self.packages.len() > MAX_FLOWS {
            errors.push(config_fail(
                "deployment.packages",
                "list one pinned package per flow, at most sixteen",
            ));
        }
        let mut roots = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for (index, package) in self.packages.iter().enumerate() {
            let field = format!("deployment.packages.{index}");
            if let Err(error) = package.check() {
                let leaf = error.field().strip_prefix("package.").unwrap_or("root");
                errors.push(config_fail(
                    &format!("{field}.{leaf}"),
                    "configure an absolute package root and pinned sha256 digest",
                ));
            }
            match &package.expected_digest {
                None => errors.push(config_fail(
                    &format!("{field}.expectedDigest"),
                    "pin the immutable package digest",
                )),
                Some(digest) if !digests.insert(digest) => errors.push(config_fail(
                    &format!("{field}.expectedDigest"),
                    "list each package once; one package serves one flow",
                )),
                Some(_) => {}
            }
            if !roots.insert(&package.root) {
                errors.push(config_fail(
                    &format!("{field}.root"),
                    "list each package directory once; one package serves one flow",
                ));
            }
        }
        if !self.listener.is_valid() {
            errors.push(config_fail(
                "deployment.listener",
                "configure a private listener with explicit TLS termination",
            ));
        }
        if let Some(metrics) = &self.metrics_listener {
            if !valid_metrics_listener(metrics.bind.socket_addr(), self.listener.bind.socket_addr())
            {
                errors.push(config_fail(
                    "deployment.metricsListener.bind",
                    "bind metricsListener to a loopback or private address with a nonzero port the listener does not use",
                ));
            }
        }
        if self.database_id.is_empty()
            || self.database_id.len() > 128
            || self.database_id.chars().any(char::is_control)
        {
            errors.push(config_fail(
                "deployment.databaseId",
                "supply the deployment's stable database identity within 128 bytes",
            ));
        }
        if !valid_identifier(&self.runtime_role) {
            errors.push(config_fail(
                "deployment.runtimeRole",
                "name the lowercase runtime PostgreSQL role within 63 bytes",
            ));
        }
        if !self.audit_path.is_absolute()
            || self.audit_path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            errors.push(config_fail(
                "deployment.auditFile",
                "use an absolute audit file path without . or .. components",
            ));
        }
        if self.active_state_key == 0
            || self.state_keys.is_empty()
            || self.state_keys.len() > 16
            || !self
                .state_keys
                .contains_key(&self.active_state_key.to_string())
            || self
                .state_keys
                .keys()
                .any(|key| match key.parse::<std::num::NonZeroU32>() {
                    Ok(id) => id.to_string() != *key,
                    Err(_) => true,
                })
        {
            errors.push(config_fail("deployment.stateKeys", "configure 1..=16 deployment.stateKeys with canonical nonzero u32 versions and select an existing version in deployment.activeStateKey"));
        }
        errors.extend(self.authentication.findings(secrets, self.local()));
        for (field, r) in [
            ("deployment.auditKeyRef", &self.audit_key_ref),
            ("deployment.admissionKeyRef", &self.admission_key_ref),
        ] {
            if secrets.check_reference(field, r.as_str()).is_err() {
                errors.push(config_fail(field, "enable each referenced secret provider"));
            }
        }
        for (version, r) in &self.state_keys {
            let field = format!("deployment.stateKeys.{version}.keyRef");
            if secrets.check_reference(&field, r.as_str()).is_err() {
                errors.push(config_fail(&field, "enable each state-key secret provider"));
            }
        }
        errors
    }
}
/// The most flows one deployment serves, so the worker's definition cache
/// and every per-flow plan stay bounded.
pub const MAX_FLOWS: usize = 16;
fn valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_lowercase() || i > 0 && b.is_ascii_digit())
}
fn fail(advice: &str) -> CoordinatorError {
    CoordinatorError::new("deployment.refused", "the deployment contract was refused")
        .suggest(advice)
}
/// The metrics listener serves operator data, so it binds only a loopback or
/// private address on its own nonzero port, never a wildcard and never the
/// socket the public listener already covers. The rule is Messaging's.
fn valid_metrics_listener(metrics: SocketAddr, listener: SocketAddr) -> bool {
    let address = metrics.ip();
    let private = match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || is_unique_local(address),
    };
    if metrics.port() == 0 || !private || address.is_unspecified() || address.is_multicast() {
        return false;
    }
    // An IPv6 wildcard socket is commonly dual-stack, so it covers both
    // families; the IPv4 wildcard covers only IPv4.
    let wildcard_covers_metrics = match listener.ip() {
        IpAddr::V4(listener) => listener.is_unspecified() && address.is_ipv4(),
        IpAddr::V6(listener) => listener.is_unspecified(),
    };
    !((address == listener.ip() || wildcard_covers_metrics) && metrics.port() == listener.port())
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn config_fail(field: &str, advice: &str) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.deployment.configuration",
        "the deployment configuration was refused",
    )
    .at("runtime.yaml", crate::runtime::pointer(field))
    .suggest(advice)
}
fn limits() -> PackageLimits {
    PackageLimits {
        max_files: 3,
        max_file_bytes: MAX_SNAPSHOT_BYTES as u64,
        max_total_bytes: MAX_SNAPSHOT_BYTES as u64,
        max_depth: 1,
        max_path_bytes: 64,
    }
}
pub struct LoadedPackage {
    pub definition: Arc<Definition>,
    pub digest: String,
}
/// The verified packages one deployment serves, keyed by flow (the package's
/// workflow id), and the digest that identifies the whole set.
pub struct Flows {
    packages: BTreeMap<String, Arc<LoadedPackage>>,
    digest: String,
}
impl Flows {
    pub fn get(&self, flow: &str) -> Option<&Arc<LoadedPackage>> {
        self.packages.get(flow)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<LoadedPackage>)> {
        self.packages.iter()
    }
    pub fn len(&self) -> usize {
        self.packages.len()
    }
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
    /// The set digest the activation ledger and control row record.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn package_digests(&self) -> BTreeMap<String, String> {
        self.packages
            .iter()
            .map(|(flow, package)| (flow.clone(), package.digest.clone()))
            .collect()
    }
    /// Every flow's workflow must bind to configured connections.
    pub fn validate(&self, runtime: &RuntimeConfig) -> Result<()> {
        for package in self.packages.values() {
            runtime.validate_workflow(&package.definition.workflow)?;
        }
        Ok(())
    }
}
/// The order-independent identity of a set of package digests. A package
/// digest fixes its workflow id, so this also identifies the flows served.
fn set_digest<'a>(digests: impl IntoIterator<Item = &'a str>) -> String {
    let sorted: BTreeSet<&str> = digests.into_iter().collect();
    let bytes = serde_json::to_vec(&sorted).expect("a list of strings encodes as JSON");
    registry_platform_config::sha256_uri(&bytes)
}
/// The set digest of the configured pins, without reading the packages.
pub fn flows_digest(config: &DeploymentConfig) -> Result<String> {
    let digests = config
        .packages
        .iter()
        .map(|package| package.expected_digest.as_deref())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| fail("pin every package digest in deployment.packages"))?;
    Ok(set_digest(digests))
}
/// Verify every pinned package and key it by its workflow id.
pub fn load_flows(config: &DeploymentConfig) -> Result<Flows> {
    if config.packages.is_empty() {
        return Err(config_fail(
            "deployment.packages",
            "list one pinned package per flow, at most sixteen",
        ));
    }
    let mut packages = BTreeMap::new();
    for (index, pin) in config.packages.iter().enumerate() {
        let field = crate::runtime::pointer(&format!("deployment.packages.{index}"));
        let package = load_package(pin).map_err(|error| error.at("runtime.yaml", field.clone()))?;
        let flow = package.definition.workflow.id.clone();
        if packages.contains_key(&flow) {
            return Err(config_fail(
                &field,
                &format!(
                    "list one package per flow; an earlier package already serves flow {flow}"
                ),
            ));
        }
        packages.insert(flow, Arc::new(package));
    }
    let digest = set_digest(packages.values().map(|package| package.digest.as_str()));
    Ok(Flows { packages, digest })
}
/// Write a checked project as a package into a new directory. A project
/// with a scenarios file is packaged only when every case passes.
pub fn package(project: &Path, output: &Path) -> Result<String> {
    let (definition, workflow) = Definition::load_project(project)?;
    let scenarios = project.join("scenarios.yaml");
    if std::fs::symlink_metadata(&scenarios).is_ok() {
        passing_scenarios(&definition, &workflow, &scenarios)?;
    }
    let files = BTreeMap::from([(
        "definition.json".into(),
        definition.snapshot()?.into_bytes(),
    )]);
    write_package(output, &files, None, &limits(), "coordinatorctl package")
        .map(|p| p.digest().to_owned())
        .map_err(|error| {
            CoordinatorError::new("package.refused", error.to_string()).suggest(
                "Name a directory that does not exist yet with --output; a package is written once and never changed in place.",
            )
        })
}
fn passing_scenarios(definition: &Definition, workflow: &Document, path: &Path) -> Result<()> {
    let (scenarios, document) = crate::scenarios::load_with_document(path)?;
    let (cases, mut diagnostics) =
        crate::scenarios::run_project(definition, workflow, &document, &scenarios);
    let failed = cases
        .iter()
        .filter(|case| case["status"] == "failed")
        .count();
    if failed == 0 && diagnostics.is_empty() {
        return Ok(());
    }
    let mut refusal = Diagnostic::error(
        "coordinator.package.scenarios-failed",
        "",
        format!(
            "{failed} of {} scenario cases failed, so nothing was packaged",
            cases.len()
        ),
        "Correct the findings that follow, run `coordinatorctl test --project DIR` until every case passes, then package again.",
    );
    refusal.source = Some(Source {
        file: path.display().to_string(),
        line: None,
        column: None,
    });
    diagnostics.insert(0, refusal);
    Err(CoordinatorError::from_diagnostics(&diagnostics))
}
pub fn load_package(package: &PackageConfig) -> Result<LoadedPackage> {
    let verified = package
        .verify_package(&limits(), "coordinatorctl package")
        .map_err(|_| fail("restore the exact pinned package; do not modify installed files"))?;
    if verified.files().collect::<Vec<_>>() != vec!["definition.json"] {
        return Err(fail("the package must contain exactly definition.json"));
    }
    let bytes = std::fs::read(package.root.join("definition.json"))
        .map_err(|_| fail("restore the pinned package"))?;
    if registry_platform_config::sha256_uri(&bytes)
        != verified.file_digest("definition.json").unwrap_or_default()
    {
        return Err(fail("restore the pinned package"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| fail("rebuild the package"))?;
    Ok(LoadedPackage {
        definition: Arc::new(Definition::from_snapshot(text)?),
        digest: verified.digest().into(),
    })
}
pub fn config(runtime: &RuntimeConfig) -> Result<&DeploymentConfig> {
    runtime.deployment.as_ref().ok_or_else(|| {
        fail("add the deployment block; local authoring needs no deployment credentials")
    })
}
pub async fn open(runtime: &RuntimeConfig, migration: bool) -> Result<Arc<Store>> {
    open_named(runtime, migration, None).await
}
pub async fn open_ctl(runtime: &RuntimeConfig, migration: bool) -> Result<Arc<Store>> {
    open_named(
        runtime,
        migration,
        Some(if migration { "apply" } else { "ctl" }),
    )
    .await
}
async fn open_named(
    runtime: &RuntimeConfig,
    migration: bool,
    companion: Option<&str>,
) -> Result<Arc<Store>> {
    let d = config(runtime)?;
    d.validate(&runtime.secret_providers)?;
    let secrets = runtime
        .secret_providers
        .resolver()
        .map_err(|_| fail("configure secret providers"))?;
    let mut keys = BTreeMap::new();
    for (version, r) in &d.state_keys {
        let value = secrets
            .resolve_binary_reference(r)
            .map_err(|_| fail("restore deployment.stateKeys raw binary key custody"))?;
        let key: [u8; 32] = value
            .expose_secret()
            .try_into()
            .map_err(|_| fail("state keys contain exactly 32 raw bytes"))?;
        keys.insert(
            version
                .parse::<u32>()
                .map_err(|_| fail("state-key versions must be canonical unsigned integers"))?,
            key,
        );
    }
    let admission = secrets
        .resolve_binary_reference(&d.admission_key_ref)
        .map_err(|_| fail("restore the stable deployment.admissionKeyRef binary key"))?;
    let admission: [u8; 32] = admission
        .expose_secret()
        .try_into()
        .map_err(|_| fail("admission key contains exactly 32 raw bytes"))?;
    let hash = secrets
        .resolve_binary_reference(&d.audit_key_ref)
        .map_err(|_| fail("restore deployment.auditKeyRef binary audit key custody"))?;
    let audit_profile =
        AuditProfile::production_from_secret_bytes(Zeroizing::new(hash.expose_secret().to_vec()))
            .map_err(|_| fail("supply a valid audit key"))?;
    let destination = AuditDestination::File(
        FileDestination::new(&d.audit_path)
            .map_err(|_| fail("configure an absolute durable audit file"))?,
    );
    let destination = if let Some(companion) = companion {
        destination
            .for_process(companion)
            .map_err(|_| fail("configure the apply audit file"))?
    } else {
        destination
    };
    let audit = AuditWriter::open(destination)
        .await
        .map_err(|_| fail("restore writable durable audit custody"))?;
    let security = StoreSecurity {
        database_id: d.database_id.clone(),
        keys: StateKeys::new(d.active_state_key, keys, admission)?,
        audit,
        audit_profile,
    };
    let raw = if migration {
        secrets
            .resolve(&runtime.database.migration_url_ref)
            .map_err(|_| fail("restore the migration database secret"))?
    } else {
        secrets
            .resolve(&runtime.database.runtime_url_ref)
            .map_err(|_| fail("restore the runtime database secret"))?
    };
    let url = std::str::from_utf8(raw.expose_secret())
        .map_err(|_| fail("database reference must resolve to UTF-8"))?;
    let tls = if d.local() && runtime.database.trusted_root_certificate_ref.is_none() {
        None
    } else {
        Some(tls(&runtime.database, &secrets)?)
    };
    let store = Store::open(url, &runtime.namespace, security, tls).await?;
    let store = if migration {
        store
    } else {
        store.with_flows_digest(flows_digest(d)?)
    };
    Ok(Arc::new(store))
}
fn tls(
    database: &DatabaseConfig,
    secrets: &registry_platform_config::SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(r) = &database.trusted_root_certificate_ref {
        let value = secrets
            .resolve(r)
            .map_err(|_| fail("make the database TLS root available"))?;
        use rustls::pki_types::pem::PemObject as _;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(value.expose_secret()) {
            roots
                .add(cert.map_err(|_| fail("supply valid PEM certificates"))?)
                .map_err(|_| fail("supply valid PEM certificates"))?;
        }
        if roots.is_empty() {
            return Err(fail("supply at least one trusted database root"));
        }
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|v| v.0)
            .map_err(|_| fail("install database TLS roots"))
    }
}
/// The activation migration ledger records the one protected state schema version.
const SCHEMA_VERSION: i64 = crate::store::SCHEMA_VERSION as i64;

fn layout() -> Result<Layout> {
    Layout::new(
        "coordinator",
        "coordinator_activations",
        "coordinator_migrations",
        &[],
        true,
    )
    .map_err(|_| fail("restore the activation layout"))
}
fn extras(namespace: &str) -> Vec<String> {
    ["runs", "jobs", "admission_lock", "review_waits"]
        .into_iter()
        .map(|s| format!("{namespace}.{s}"))
        .collect()
}
async fn check_control_role(client: &impl tokio_postgres::GenericClient, role: &str) -> Result<()> {
    let row=client.query_one("SELECT has_table_privilege($1,'control','SELECT'),has_table_privilege($1,'control','INSERT,DELETE,TRUNCATE') OR has_column_privilege($1,'control','id','UPDATE') OR has_column_privilege($1,'control','database_id','UPDATE') OR has_column_privilege($1,'control','schema_version','UPDATE') OR has_column_privilege($1,'control','active_flows_digest','UPDATE') OR has_column_privilege($1,'control','active_flows','UPDATE') OR has_column_privilege($1,'control','admission_key_commitment','UPDATE') OR has_column_privilege($1,'control','state_key_commitments','UPDATE'),has_column_privilege($1,'control','restore_hold','UPDATE') AND has_column_privilege($1,'control','admissions_hold','UPDATE') AND has_column_privilege($1,'control','restore_evidence_hash','UPDATE') AND has_column_privilege($1,'control','admission_recovery_hash','UPDATE')",&[&role]).await.map_err(|_|fail("restore the narrow runtime control grants"))?;
    if !row.get::<_, bool>(0) || row.get::<_, bool>(1) || !row.get::<_, bool>(2) {
        return Err(fail("runtime may update recovery hold columns only; remove immutable control write authority"));
    }
    Ok(())
}
pub async fn check(
    store: &Store,
    runtime: &RuntimeConfig,
    digest: &str,
) -> Result<activation::Activation> {
    let d = config(runtime)?;
    // Unreachable is not refused: the service waits this out and checks again.
    let client = store.client().await.map_err(|_| {
        CoordinatorError::new("store-unavailable", "durable state is unavailable")
            .suggest("restore database connectivity")
    })?;
    let l = layout()?;
    let active = activation::check_active_package(&*client, &l, &d.database_id, digest)
        .await
        .map_err(|_| {
            fail("run coordinatorctl plan/apply with the correct database identity and packages, then restart every service")
        })?;
    let schema = activation::schema_state(&*client, &l, &[SCHEMA_VERSION])
        .await
        .map_err(|_| fail("restore the migration ledger"))?;
    if schema.applied != [SCHEMA_VERSION] || !schema.pending.is_empty() {
        return Err(fail("apply the supported schema version before serving"));
    }
    let role = activation::observe_role(&*client, &l, None, &extras(&runtime.namespace))
        .await
        .map_err(|_| fail("restore runtime grants"))?
        .ok_or_else(|| fail("restore runtime role"))?;
    if role.mode != RoleMode::Split || !role.grants_current {
        return Err(fail(
            "apply least-privileged split-role grants before serving",
        ));
    }
    let current: String = client
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(|_| fail("observe the runtime role"))?
        .get(0);
    if current != d.runtime_role || active.runtime_role.as_deref() != Some(current.as_str()) {
        return Err(fail(
            "use database.runtimeUrlRef for the configured runtimeRole and apply that same role to the activation ledger",
        ));
    }
    check_control_role(&*client, &current).await?;
    // Worker transactions verify the same custody but can only report that
    // durable state is unavailable, so the check names a custody mismatch.
    let custody = client
        .query_one(
            &format!(
                "SELECT database_id,admission_key_commitment,state_key_commitments FROM {}.control WHERE id",
                runtime.namespace
            ),
            &[],
        )
        .await
        .map_err(|_| fail("restore the protected control row"))?;
    store.verify_registered_custody(
        &custody.get::<_, String>(0),
        &custody.get::<_, String>(1),
        &custody.get::<_, serde_json::Value>(2),
        false,
    )?;
    Ok(active)
}
/// Check retained runnable/recoverable bindings before normal serving or an
/// explicit operator status observation. Readiness bounds the frequency of its
/// live-binding scan; worker transactions retain their fresh protected gates.
pub async fn check_serving(
    store: &Store,
    runtime: &RuntimeConfig,
    digest: &str,
) -> Result<activation::Activation> {
    let active = check(store, runtime, digest).await?;
    store.check_runtime_bindings(runtime).await?;
    Ok(active)
}
/// What one plan or apply does to one flow's active package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    Install,
    Replace,
    Unchanged,
    Remove,
}
impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Replace => "replace",
            Self::Unchanged => "unchanged",
            Self::Remove => "remove",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowChange {
    pub flow: String,
    pub change: Change,
    /// The package this flow serves after the change; absent for a removal.
    pub package_digest: Option<String>,
    /// The package this flow served before the change; absent for an install.
    pub active_package_digest: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Applied {
    pub activation: activation::Activation,
    pub flows_digest: String,
    pub flows: Vec<FlowChange>,
}
/// Compare the listed flows with the active ones. An active flow missing from
/// the list is removed only when named, so editing the list never silently
/// retires a flow.
fn flow_changes(
    flows: &Flows,
    active: &BTreeMap<String, String>,
    remove: &[String],
) -> Result<Vec<FlowChange>> {
    let remove: BTreeSet<&str> = remove.iter().map(String::as_str).collect();
    for flow in &remove {
        if flows.get(flow).is_some() {
            return Err(fail(&format!(
                "flow {flow} is still listed in deployment.packages; drop its package from the list to remove it"
            )));
        }
        if !active.contains_key(*flow) {
            return Err(fail(&format!(
                "flow {flow} is not active; name only active flows with --remove-flow"
            )));
        }
    }
    let mut changes = Vec::new();
    for (flow, package) in flows.iter() {
        let active = active.get(flow);
        changes.push(FlowChange {
            flow: flow.clone(),
            change: match active {
                None => Change::Install,
                Some(digest) if *digest == package.digest => Change::Unchanged,
                Some(_) => Change::Replace,
            },
            package_digest: Some(package.digest.clone()),
            active_package_digest: active.cloned(),
        });
    }
    for (flow, digest) in active {
        if flows.get(flow).is_some() {
            continue;
        }
        if !remove.contains(flow.as_str()) {
            return Err(CoordinatorError::new(
                "deployment.flow-unlisted",
                "an active flow is missing from deployment.packages",
            )
            .suggest(format!(
                "list flow {flow}'s package again, or pass --remove-flow {flow} to retire it once its runs are terminal"
            )));
        }
        changes.push(FlowChange {
            flow: flow.clone(),
            change: Change::Remove,
            package_digest: None,
            active_package_digest: Some(digest.clone()),
        });
    }
    changes.sort_by(|a, b| a.flow.cmp(&b.flow));
    Ok(changes)
}
/// The flows the control row records as active, or none before the first apply.
async fn active_flows(
    client: &impl tokio_postgres::GenericClient,
    namespace: &str,
) -> Result<BTreeMap<String, String>> {
    let exists: bool = client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("{namespace}.control")],
        )
        .await
        .map_err(|_| fail("restore database connectivity"))?
        .get(0);
    if !exists {
        return Ok(BTreeMap::new());
    }
    let Some(row) = client
        .query_opt(
            &format!("SELECT active_flows FROM {namespace}.control WHERE id"),
            &[],
        )
        .await
        .map_err(|_| fail("restore the active flow record"))?
    else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_value(row.get::<_, serde_json::Value>(0))
        .map_err(|_| fail("restore the active flow record"))
}
/// Refuse to retire a flow while any of its runs could still act or needs review.
async fn check_removals(
    store: &Store,
    client: &impl tokio_postgres::GenericClient,
    changes: &[FlowChange],
) -> Result<()> {
    for change in changes.iter().filter(|c| c.change == Change::Remove) {
        let live = store.live_runs(client, &change.flow).await?;
        if live > 0 {
            return Err(CoordinatorError::new(
                "deployment.flow-live-runs",
                "a flow with runs that are not terminal cannot be removed",
            )
            .suggest(format!(
                "flow {} has {live} runs that are not terminal; let them settle or cancel them, or keep its package listed",
                change.flow
            )));
        }
    }
    Ok(())
}
/// Refuse a listed package whose workflow version already names another
/// definition in run history, naming the flow to fix.
async fn check_versions(
    store: &Store,
    client: &impl tokio_postgres::GenericClient,
    flows: &Flows,
) -> Result<()> {
    for (flow, package) in flows.iter() {
        store
            .check_definition_history(client, &package.definition)
            .await
            .map_err(|error| {
                if error.code == "workflow-version-conflict" {
                    error.suggest(format!(
                        "give flow {flow}'s changed definition a new project.version in its workflow.yaml, then package it and list that package"
                    ))
                } else {
                    error
                }
            })?;
    }
    Ok(())
}
pub async fn plan(
    store: &Store,
    runtime: &RuntimeConfig,
    flows: &Flows,
    remove: &[String],
) -> Result<serde_json::Value> {
    let d = config(runtime)?;
    let client = store
        .client()
        .await
        .map_err(|_| fail("restore database connectivity"))?;
    let l = layout()?;
    let active = activation::active_activation(&*client, &l)
        .await
        .map_err(|_| fail("restore the activation ledger"))?;
    let schema = activation::schema_state(&*client, &l, &[SCHEMA_VERSION])
        .await
        .map_err(|_| fail("restore the migration ledger"))?;
    let changes = flow_changes(
        flows,
        &active_flows(&*client, &runtime.namespace).await?,
        remove,
    )?;
    check_removals(store, &*client, &changes).await?;
    let history: bool = client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("{}.runs", runtime.namespace)],
        )
        .await
        .map_err(|_| fail("restore database connectivity"))?
        .get(0);
    if history {
        check_versions(store, &*client, flows).await?;
    }
    Ok(
        serde_json::json!({"databaseId":d.database_id,"flowsDigest":flows.digest(),"flows":changes,"active":active,"schema":{"applied":schema.applied,"pending":schema.pending},"runtimeRole":d.runtime_role}),
    )
}
/// Activate the listed flows in one transaction. Each flow's package is
/// installed, replaced or kept on its own; a flow is removed only when named
/// in `remove` and has no run that is not terminal.
pub async fn apply(
    store: &Store,
    runtime: &RuntimeConfig,
    flows: &Flows,
    remove: &[String],
) -> Result<Applied> {
    let d = config(runtime)?;
    flows.validate(runtime)?;
    let audit = store
        .audit_writer()
        .begin(
            AUDIT_SCHEMA,
            Uuid::new_v4().to_string(),
            serde_json::json!({"action":"activation.apply","flowsDigest":flows.digest(),"flows":flows.package_digests(),"removeFlows":remove}),
            serde_json::json!({"outcome":"unknown"}),
        )
        .await
        .map_err(|_| fail("restore durable apply audit before changing deployment state"))?;
    let mut client = store
        .client()
        .await
        .map_err(|_| fail("restore migration database connectivity"))?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| fail("restore migration database connectivity"))?;

    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        &[&runtime.namespace],
    )
    .await
    .map_err(|_| fail("restore activation locking"))?;
    let l = layout()?;
    store.migrate_in(&tx).await?;
    tx.batch_execute(&format!(
        "SET LOCAL search_path TO {},pg_catalog",
        runtime.namespace
    ))
    .await
    .map_err(|_| fail("restore schema search path"))?;
    if activation::default_trigger_grant(&tx, &d.runtime_role)
        .await
        .map_err(|_| fail("inspect migration default grants"))?
        .is_some()
    {
        return Err(fail("remove default TRIGGER grants to the runtime role"));
    }
    tx.batch_execute(&format!("CREATE TABLE IF NOT EXISTS coordinator_migrations(version bigint PRIMARY KEY); INSERT INTO coordinator_migrations VALUES({SCHEMA_VERSION}) ON CONFLICT DO NOTHING; CREATE TABLE IF NOT EXISTS coordinator_activations(activation_id uuid PRIMARY KEY,apply_order bigint UNIQUE NOT NULL,package_digest text NOT NULL,predecessor_package_digest text,database_id text NOT NULL,plan_kind text NOT NULL,applied_at timestamptz NOT NULL,operator_reference_hash text,backup_references text[] NOT NULL,role_mode text NOT NULL,runtime_role text NOT NULL)")).await.map_err(|_|fail("restore activation schema"))?;
    let prior = activation::active_activation(&tx, &l)
        .await
        .map_err(|_| fail("restore ledger"))?;
    if prior
        .as_ref()
        .is_some_and(|a| a.database_id != d.database_id)
    {
        return Err(fail("use the deployment's recorded database identity"));
    }
    let changes = flow_changes(flows, &active_flows(&tx, &runtime.namespace).await?, remove)?;
    store.check_live_bindings(&tx, runtime).await?;
    check_removals(store, &tx, &changes).await?;
    check_versions(store, &tx, flows).await?;
    activation::grant_runtime_role(&tx, &l, &d.runtime_role, &extras(&runtime.namespace))
        .await
        .map_err(|_| fail("grant the configured runtime role"))?;
    tx.batch_execute(&format!("REVOKE ALL ON control FROM PUBLIC; REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control FROM {}; GRANT SELECT, UPDATE(restore_hold,admissions_hold,restore_evidence_hash,admission_recovery_hash) ON control TO {}",d.runtime_role,d.runtime_role)).await.map_err(|_|fail("grant only mutable recovery columns to the runtime role"))?;
    check_control_role(&tx, &d.runtime_role).await?;
    let role =
        activation::observe_role(&tx, &l, Some(&d.runtime_role), &extras(&runtime.namespace))
            .await
            .map_err(|_| fail("inspect runtime role authority"))?
            .ok_or_else(|| fail("create the runtime role before apply"))?;
    if role.mode != RoleMode::Split || !role.grants_current {
        return Err(fail(
            "runtime role must not own the schema, migrate or write activation ledgers",
        ));
    }
    let request = NewActivation {
        activation_id: Uuid::new_v4(),
        package_digest: flows.digest(),
        database_id: &d.database_id,
        operator_reference_hash: None,
        backup_references: &[],
        role_mode: RoleMode::Split,
        runtime_role: Some(&d.runtime_role),
    };
    let active = activation::append_activation(&tx, &l, &request)
        .await
        .map_err(|_| fail("restore activation ledger"))?;
    let active_flows = serde_json::to_value(flows.package_digests())
        .map_err(|_| fail("encode the active flow record"))?;
    tx.execute(
        "UPDATE control SET active_flows_digest=$1,active_flows=$2 WHERE id",
        &[&flows.digest(), &active_flows],
    )
    .await
    .map_err(|_| fail("restore active flow control identity"))?;
    tx.commit().await.map_err(|_| {
        fail("activation commit is unknown; inspect deployment status before repeating apply")
    })?;
    audit.finish(serde_json::json!({"outcome":"applied","activationId":active.activation_id,"flowsDigest":active.package_digest,"flows":changes})).await.map_err(|_|fail("activation committed but audit outcome is unavailable; inspect deployment status before continuing"))?;
    Ok(Applied {
        activation: active,
        flows_digest: flows.digest().to_owned(),
        flows: changes,
    })
}

#[cfg(test)]
mod tests {
    use super::valid_metrics_listener;

    #[test]
    fn the_metrics_listener_may_not_share_a_wildcard_listener_port() {
        assert!(!valid_metrics_listener(
            "10.0.0.5:8108".parse().unwrap(),
            "0.0.0.0:8108".parse().unwrap()
        ));
        assert!(!valid_metrics_listener(
            "10.0.0.5:8108".parse().unwrap(),
            "[::]:8108".parse().unwrap()
        ));
        assert!(valid_metrics_listener(
            "[fd00::5]:8108".parse().unwrap(),
            "0.0.0.0:8108".parse().unwrap()
        ));
        assert!(valid_metrics_listener(
            "10.0.0.5:9108".parse().unwrap(),
            "0.0.0.0:8108".parse().unwrap()
        ));
    }
}
