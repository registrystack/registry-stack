// SPDX-License-Identifier: Apache-2.0
//! Immutable package loading and explicit PostgreSQL activation.
use crate::{
    access::AccessConfig,
    definition::{Definition, MAX_SNAPSHOT_BYTES},
    protected_state::StateKeys,
    runtime::RuntimeConfig,
    store::{Store, StoreSecurity, AUDIT_SCHEMA},
    PocError, Result,
};
use registry_platform_activation::{self as activation, Layout, NewActivation, RoleMode};
use registry_platform_audit::{AuditDestination, AuditProfile, AuditWriter, FileDestination};
use registry_platform_config::{
    package::{write_package, PackageLimits},
    DatabaseConfig, PackageConfig, PrivateListenerConfig, SecretProvidersConfig, SecretReference,
    TlsTermination,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
    pub package: PackageConfig,
    pub listener: PrivateListenerConfig,
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
    pub(crate) fn findings(&self, secrets: &SecretProvidersConfig) -> Vec<PocError> {
        let mut errors = Vec::new();
        if let Err(error) = self.package.check() {
            errors.push(config_fail(
                error.field(),
                "configure an absolute package root and pinned sha256 digest",
            ));
        }
        if self.package.expected_digest.is_none() {
            errors.push(config_fail(
                "deployment.package.expectedDigest",
                "pin the immutable package digest",
            ));
        }
        if !self.listener.is_valid() {
            errors.push(config_fail(
                "deployment.listener",
                "configure a private listener with explicit TLS termination",
            ));
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
fn valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_lowercase() || i > 0 && b.is_ascii_digit())
}
fn fail(advice: &str) -> PocError {
    PocError::new(
        "coordinator.deployment.refused",
        "the deployment contract was refused",
    )
    .suggest(advice)
}
fn config_fail(field: &str, advice: &str) -> PocError {
    PocError::new(
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
pub fn package(project: &Path, output: &Path) -> Result<String> {
    let definition = Definition::load(project)?;
    let files = BTreeMap::from([(
        "definition.json".into(),
        definition.snapshot()?.into_bytes(),
    )]);
    write_package(output, &files, None, &limits(), "coordinatorctl package")
        .map(|p| p.digest().to_owned())
        .map_err(|_| fail("write a new package directory from a checked project"))
}
pub fn load_package(config: &DeploymentConfig) -> Result<LoadedPackage> {
    let verified = config
        .package
        .verify_package(&limits(), "coordinatorctl package")
        .map_err(|_| fail("restore the exact pinned package; do not modify installed files"))?;
    if verified.files().collect::<Vec<_>>() != vec!["definition.json"] {
        return Err(fail("the package must contain exactly definition.json"));
    }
    let bytes = std::fs::read(config.package.root.join("definition.json"))
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
        store.with_package_digest(
            d.package
                .expected_digest
                .clone()
                .ok_or_else(|| fail("pin the active package digest"))?,
        )
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
/// The migration ledger of a store holds exactly its one schema revision.
const LEDGER: [i64; 1] = [crate::store::SCHEMA_VERSION as i64];
const OTHER_REVISION: &str =
    "this database records another Coordinator schema revision; apply to a new database";
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
    ["runs", "jobs", "admission_lock"]
        .into_iter()
        .map(|s| format!("{namespace}.{s}"))
        .collect()
}
async fn check_control_role(client: &impl tokio_postgres::GenericClient, role: &str) -> Result<()> {
    let row=client.query_one("SELECT has_table_privilege($1,'control','SELECT'),has_table_privilege($1,'control','INSERT,DELETE,TRUNCATE') OR has_column_privilege($1,'control','id','UPDATE') OR has_column_privilege($1,'control','database_id','UPDATE') OR has_column_privilege($1,'control','schema_version','UPDATE') OR has_column_privilege($1,'control','active_package_digest','UPDATE') OR has_column_privilege($1,'control','admission_key_commitment','UPDATE') OR has_column_privilege($1,'control','state_key_commitments','UPDATE'),has_column_privilege($1,'control','restore_hold','UPDATE') AND has_column_privilege($1,'control','admissions_hold','UPDATE') AND has_column_privilege($1,'control','restore_evidence_hash','UPDATE') AND has_column_privilege($1,'control','admission_recovery_hash','UPDATE')",&[&role]).await.map_err(|_|fail("restore the narrow runtime control grants"))?;
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
    let client = store
        .client()
        .await
        .map_err(|_| fail("restore database connectivity"))?;
    let l = layout()?;
    let active = activation::check_active_package(&client, &l, &d.database_id, digest)
        .await
        .map_err(|_| {
            fail("run coordinatorctl plan/apply with the correct database identity and package")
        })?;
    let schema = activation::schema_state(&client, &l, &LEDGER)
        .await
        .map_err(|_| fail("restore the migration ledger"))?;
    if schema.applied.is_empty() {
        return Err(fail("run coordinatorctl apply before serving"));
    }
    let recorded: i32 = client
        .query_one(
            &format!(
                "SELECT schema_version FROM {}.control WHERE id",
                runtime.namespace
            ),
            &[],
        )
        .await
        .map_err(|_| fail("restore the deployment control record"))?
        .get(0);
    if schema.applied != LEDGER || recorded != crate::store::SCHEMA_VERSION {
        return Err(fail(OTHER_REVISION));
    }
    let role = activation::observe_role(&client, &l, None, &extras(&runtime.namespace))
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
    check_control_role(&client, &current).await?;
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
pub async fn plan(
    store: &Store,
    runtime: &RuntimeConfig,
    digest: &str,
) -> Result<serde_json::Value> {
    let d = config(runtime)?;
    let client = store
        .client()
        .await
        .map_err(|_| fail("restore database connectivity"))?;
    let l = layout()?;
    let active = activation::active_activation(&client, &l)
        .await
        .map_err(|_| fail("restore the activation ledger"))?;
    let schema = activation::schema_state(&client, &l, &LEDGER)
        .await
        .map_err(|_| fail("restore the migration ledger"))?;
    Ok(
        serde_json::json!({"databaseId":d.database_id,"packageDigest":digest,"active":active,"schema":{"applied":schema.applied,"pending":schema.pending},"runtimeRole":d.runtime_role}),
    )
}
pub async fn apply(
    store: &Store,
    runtime: &RuntimeConfig,
    package: &LoadedPackage,
) -> Result<activation::Activation> {
    let d = config(runtime)?;
    runtime.validate_workflow(&package.definition.workflow)?;
    let audit = store
        .audit_writer()
        .begin(
            AUDIT_SCHEMA,
            Uuid::new_v4().to_string(),
            serde_json::json!({"action":"activation.apply","packageDigest":package.digest}),
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
    tx.batch_execute(&format!("CREATE TABLE IF NOT EXISTS coordinator_migrations(version bigint PRIMARY KEY); INSERT INTO coordinator_migrations VALUES({}) ON CONFLICT DO NOTHING; CREATE TABLE IF NOT EXISTS coordinator_activations(activation_id uuid PRIMARY KEY,apply_order bigint UNIQUE NOT NULL,package_digest text NOT NULL,predecessor_package_digest text,database_id text NOT NULL,plan_kind text NOT NULL,applied_at timestamptz NOT NULL,operator_reference_hash text,backup_references text[] NOT NULL,role_mode text NOT NULL,runtime_role text NOT NULL)", LEDGER[0])).await.map_err(|_|fail("restore activation schema"))?;
    let schema = activation::schema_state(&tx, &l, &LEDGER)
        .await
        .map_err(|_| fail("restore the migration ledger"))?;
    if schema.applied != LEDGER {
        return Err(fail(OTHER_REVISION));
    }
    let prior = activation::active_activation(&tx, &l)
        .await
        .map_err(|_| fail("restore ledger"))?;
    if prior
        .as_ref()
        .is_some_and(|a| a.database_id != d.database_id)
    {
        return Err(fail("use the deployment's recorded database identity"));
    }
    store.check_live_bindings(&tx, runtime).await?;
    store
        .check_definition_history(&tx, &package.definition)
        .await?;
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
        package_digest: &package.digest,
        database_id: &d.database_id,
        operator_reference_hash: None,
        backup_references: &[],
        role_mode: RoleMode::Split,
        runtime_role: Some(&d.runtime_role),
    };
    let active = activation::append_activation(&tx, &l, &request)
        .await
        .map_err(|_| fail("restore activation ledger"))?;
    tx.execute(
        "UPDATE control SET active_package_digest=$1 WHERE id",
        &[&package.digest],
    )
    .await
    .map_err(|_| fail("restore active package control identity"))?;
    tx.commit().await.map_err(|_| {
        fail("activation commit is unknown; inspect deployment status before repeating apply")
    })?;
    audit.finish(serde_json::json!({"outcome":"applied","activationId":active.activation_id,"packageDigest":active.package_digest})).await.map_err(|_|fail("activation committed but audit outcome is unavailable; inspect deployment status before continuing"))?;
    Ok(active)
}
