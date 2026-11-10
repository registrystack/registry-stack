// SPDX-License-Identifier: Apache-2.0
//! Operator-only inspection, withdrawal and rotation of one indexed external
//! projection's cache scope.
//!
//! Deployment configuration is the only cutoff for acquisition: a binding
//! still configured binds again at the next start. Withdrawal deactivates the
//! scope and purges its cached rows; rotation starts a fresh epoch under the
//! currently configured binding, grant and cache lifetime, and purges the old
//! one. Both run under the configured migration authority, the exclusive
//! registry lock and a catalog identity check in one transaction, and both are
//! audited. Inspection reads the scope and fixed counters only.

use std::collections::BTreeSet;
use std::{path::Path, sync::Arc, time::Duration};

use registry_platform_audit::AuditEntry;
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::audit::RegistryAudit;
use crate::external_source::ExternalSourceService;
use crate::external_views::ExternalProjectionMode;
use crate::history_maintenance::{lock_registry, HistoryMaintenanceError};
use crate::model::CompiledRegistry;
use crate::package::PackageError;
use crate::postgres::{
    lock_wait_ended, verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::{load_runtime_config, RuntimeConfig};

/// Schema of the request and response entries of one external projection
/// withdrawal or rotation.
pub const EXTERNAL_PROJECTION_AUDIT_SCHEMA: &str = "breg-external-projection-audit/v1";

const MAINTENANCE: &str =
    "SELECT registry_internal.maintain_external_projection_scope($1,$2,$3,$4,$5,$6,$7,$8)";

/// Value-free failures. Projection IDs come from the reviewed package and a
/// binding reason names the failed check, never a configured value.
#[derive(Debug, Error)]
pub enum ExternalProjectionMaintenanceError {
    #[error("the external projection maintenance request is invalid")]
    InvalidRequest,
    #[error("external projection `{0}` is not an indexed projection of the active package")]
    UnknownProjection(String),
    #[error("external projection `{projection}` has no usable binding: {reason}")]
    BindingUnavailable { projection: String, reason: String },
    #[error("external projection `{0}` has no bound scope to withdraw")]
    NotBound(String),
    #[error("another session held the exclusive migration lock past the lock timeout")]
    MigrationLockHeld,
    #[error("the active package does not match its configured pin")]
    PackagePinMismatch(registry_platform_config::blocks::PackageDigestMismatch),
    #[error("external projection maintenance is unavailable")]
    Unavailable,
}

type Result<T> = std::result::Result<T, ExternalProjectionMaintenanceError>;
use ExternalProjectionMaintenanceError as Error;

/// The cache scope a configured binding asks for, as startup computes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredScope {
    pub binding_digest: String,
    pub grant_digest: String,
    pub cache_ttl_seconds: i64,
}

/// The scope the loaded bindings ask for `projection`. A projection whose
/// binding failed its own checks, or that has none, is refused with the reason.
pub(crate) fn scope_from_sources(
    sources: &ExternalSourceService,
    projection: &str,
) -> Result<ConfiguredScope> {
    let refused = || Error::BindingUnavailable {
        projection: projection.to_owned(),
        reason: sources
            .unavailable_projections()
            .get(projection)
            .cloned()
            .unwrap_or_else(|| "no external source is bound to this projection".to_owned()),
    };
    let bound = sources.binding(projection).ok_or_else(refused)?;
    let ttl = bound.effective_cache_ttl_seconds().ok_or_else(refused)?;
    Ok(ConfiguredScope {
        binding_digest: bound.binding_fingerprint().to_owned(),
        grant_digest: bound.grant_fingerprint().to_owned(),
        cache_ttl_seconds: i64::from(ttl),
    })
}

/// The scope the runtime configuration's binding asks for `projection`. Pack
/// and public TLS material are read; no credential is resolved and no source
/// is called.
pub fn configured_scope(
    registry: &CompiledRegistry,
    config: &RuntimeConfig,
    projection: &str,
) -> Result<ConfiguredScope> {
    let resolver = config.secret_resolver().map_err(|_| Error::Unavailable)?;
    let sources =
        ExternalSourceService::load(registry, config.external_sources(), Arc::new(resolver))
            .map_err(|error| Error::BindingUnavailable {
                projection: projection.to_owned(),
                reason: error.to_string(),
            })?;
    scope_from_sources(&sources, projection)
}

fn indexed_projections(registry: &CompiledRegistry) -> BTreeSet<String> {
    registry
        .external_views()
        .projections
        .values()
        .filter(|projection| projection.mode == ExternalProjectionMode::Indexed)
        .map(|projection| projection.id.to_string())
        .collect()
}

/// The stored scope row, read to tell a committed change from a rolled-back
/// one. Every withdrawal and rotation moves the generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScopeMark {
    epoch: Uuid,
    generation: i64,
}

async fn scope_mark(
    client: &impl tokio_postgres::GenericClient,
    projection: &str,
) -> Result<Option<ScopeMark>> {
    Ok(client
        .query_opt(
            "SELECT epoch, generation FROM registry_internal.registry_external_projection_scopes
             WHERE projection_id=$1",
            &[&projection],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .map(|row| ScopeMark {
            epoch: row.get(0),
            generation: row.get(1),
        }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Withdraw,
    Rotate,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Withdraw => "withdraw",
            Self::Rotate => "rotate",
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            Self::Withdraw => "withdrawn",
            Self::Rotate => "rotated",
        }
    }
}

/// How a maintenance transaction ended once every statement in it succeeded.
enum Change {
    Committed(Value),
    Unacknowledged {
        scope: Value,
        before: Option<ScopeMark>,
        after: Option<ScopeMark>,
    },
}

/// Package-bound authority over the indexed external projection scopes. The
/// migration identity, actual target catalog and registry interlock are checked
/// again in the same transaction that changes a scope.
pub struct ExternalProjectionOperatorService {
    indexed: BTreeSet<String>,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_timeout: Duration,
    statement_timeout: Duration,
    audit: RegistryAudit,
}

impl ExternalProjectionOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self> {
        Ok(Self::open(path).await?.0)
    }

    /// The service, its configuration and the active package's registry.
    async fn open(path: &Path) -> Result<(Self, RuntimeConfig, CompiledRegistry)> {
        if !path.is_absolute() {
            return Err(Error::InvalidRequest);
        }
        let config = load_runtime_config(path).map_err(|_| Error::Unavailable)?;
        let package = config.load_active_package().map_err(|error| match error {
            PackageError::ExpectedDigestMismatch(mismatch) => Error::PackagePinMismatch(mismatch),
            _ => Error::Unavailable,
        })?;
        let pool = config
            .runtime_database_connection_config()
            .map_err(|_| Error::Unavailable)?
            .build_pool()
            .map_err(|_| Error::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| Error::Unavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        let registry = startup.package().registry().clone();
        let service = Self {
            indexed: indexed_projections(&registry),
            expected: startup.expected_identity().clone(),
            expected_catalog: startup.expected_catalog().clone(),
            lock_key: startup.lock_key(),
            migration_connection: config
                .migration_database_connection_config()
                .map_err(|_| Error::Unavailable)?,
            migration_role: config.database().roles().migration().clone(),
            runtime_role: config.database().roles().runtime().clone(),
            lock_timeout: config.operational_timeouts().migration_lock,
            statement_timeout: config.operational_timeouts().migration_statement,
            audit: RegistryAudit::open_companion(&config)
                .await
                .map_err(|_| Error::Unavailable)?,
        };
        Ok((service, config, registry))
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn new_for_test(
        registry: &CompiledRegistry,
        expected: ExpectedRegistryIdentity,
        migration_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit: RegistryAudit,
    ) -> Self {
        Self {
            indexed: indexed_projections(registry),
            expected,
            expected_catalog: ExpectedManagedCatalog::compiled(registry),
            lock_key: RegistryLockKey::derive(registry.registry_id())
                .expect("the registry lock key derives"),
            migration_connection,
            migration_role,
            runtime_role,
            lock_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            audit,
        }
    }

    fn require_indexed(&self, projection: &str) -> Result<()> {
        if self.indexed.contains(projection) {
            Ok(())
        } else {
            Err(Error::UnknownProjection(projection.to_owned()))
        }
    }

    /// The projection's scope, its fixed refresh outcome counts and its
    /// snapshot counts. Nothing is changed and no source value is read.
    pub async fn inspect(&self, projection: &str) -> Result<Value> {
        self.require_indexed(projection)?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| Error::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| Error::Unavailable)?;
        let client: &mut tokio_postgres::Client = &mut client;
        let transaction = self.open_transaction(client).await?;
        transaction
            .execute(
                "SELECT pg_catalog.pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(lock_failure)?;
        self.verify_catalog(&transaction).await?;
        let scope = self
            .call(&transaction, "inspect", projection, None, None)
            .await?;
        transaction
            .rollback()
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(scope)
    }

    /// Deactivate the projection's scope under its current epoch and purge its
    /// cached rows. Acquisition stops only when the binding leaves the
    /// deployment configuration; a binding still configured binds again at
    /// the next start.
    pub async fn withdraw(&self, projection: &str) -> Result<Value> {
        self.require_indexed(projection)?;
        self.audited(Action::Withdraw, projection, None).await
    }

    /// Start a fresh epoch under `configured` and purge the projection's
    /// cached rows. Earlier epochs are never readable again.
    pub async fn rotate(&self, projection: &str, configured: &ConfiguredScope) -> Result<Value> {
        self.require_indexed(projection)?;
        self.audited(Action::Rotate, projection, Some(configured))
            .await
    }

    /// The request entry is accepted before the transaction opens, so an
    /// audit outage changes nothing. Its response records the outcome the
    /// database holds.
    async fn audited(
        &self,
        action: Action,
        projection: &str,
        configured: Option<&ConfiguredScope>,
    ) -> Result<Value> {
        let correlation = Uuid::new_v4().to_string();
        let record = |phase: &str, outcome: &str| -> Value {
            json!({
                "kind": "externalProjectionMaintenance",
                "action": action.name(),
                "projection": projection,
                "phase": phase,
                "outcome": outcome,
                "activationId": self.expected.activation_id,
                "actor": "breg:external-projection-operator",
                "correlation": correlation,
            })
        };
        let mut attempt = self
            .audit
            .begin(
                AuditEntry::request(
                    EXTERNAL_PROJECTION_AUDIT_SCHEMA,
                    correlation.clone(),
                    record("attempt", "started"),
                ),
                record("terminal", "unfinished"),
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        let changed = match self
            .change_in_transaction(action, projection, configured)
            .await
        {
            Ok(Change::Committed(scope)) => Ok(scope),
            // A commit that returned an error may still have committed, so the
            // outcome recorded is the one the database holds, read on a fresh
            // connection.
            Ok(Change::Unacknowledged {
                scope,
                before,
                after,
            }) => match self.stored_mark(projection).await {
                Some(stored) if stored == after => Ok(scope),
                resolved => {
                    let outcome = if resolved == Some(before) {
                        "failed"
                    } else {
                        "unfinished"
                    };
                    if attempt.respond(record("terminal", outcome)).await.is_err() {
                        tracing::error!(
                            "the unacknowledged external projection maintenance's response audit entry was not recorded"
                        );
                    }
                    return Err(Error::Unavailable);
                }
            },
            Err(error) => Err(error),
        };
        match changed {
            Ok(scope) => {
                let mut response = record("terminal", action.outcome());
                response["epoch"] = scope["epoch"].clone();
                // The change committed; a refused entry reports the command
                // unavailable, and the writer then refuses every later entry.
                attempt
                    .respond(response)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                Ok(scope)
            }
            Err(error) => {
                if attempt.respond(record("terminal", "failed")).await.is_err() {
                    tracing::error!(
                        "the failed external projection maintenance's response audit entry was not recorded"
                    );
                }
                Err(error)
            }
        }
    }

    /// The stored scope row read on a fresh connection, `None` inside when no
    /// row exists, and `None` outside when it cannot be read.
    async fn stored_mark(&self, projection: &str) -> Option<Option<ScopeMark>> {
        let pool = self.migration_connection.build_pool().ok()?;
        let client = pool.get().await.ok()?;
        let client: &tokio_postgres::Client = &client;
        scope_mark(client, projection).await.ok()
    }

    async fn change_in_transaction(
        &self,
        action: Action,
        projection: &str,
        configured: Option<&ConfiguredScope>,
    ) -> Result<Change> {
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| Error::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| Error::Unavailable)?;
        let client: &mut tokio_postgres::Client = &mut client;
        let transaction = self.open_transaction(client).await?;
        lock_registry(&transaction, self.lock_key)
            .await
            .map_err(|error| match error {
                HistoryMaintenanceError::MigrationLockHeld => Error::MigrationLockHeld,
                _ => Error::Unavailable,
            })?;
        self.verify_catalog(&transaction).await?;
        let before = scope_mark(&transaction, projection).await?;
        if action == Action::Withdraw && before.is_none() {
            return Err(Error::NotBound(projection.to_owned()));
        }
        let scope = self
            .call(
                &transaction,
                action.name(),
                projection,
                before.map(|mark| mark.epoch),
                configured,
            )
            .await?;
        let after = scope_mark(&transaction, projection).await?;
        if transaction.commit().await.is_err() {
            return Ok(Change::Unacknowledged {
                scope,
                before,
                after,
            });
        }
        Ok(Change::Committed(scope))
    }

    async fn open_transaction<'a>(
        &self,
        client: &'a mut tokio_postgres::Client,
    ) -> Result<tokio_postgres::Transaction<'a>> {
        verify_migration_role(client, &self.migration_role)
            .await
            .map_err(|_| Error::Unavailable)?;
        let transaction = client.transaction().await.map_err(|_| Error::Unavailable)?;
        transaction
            .query_one(
                "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
                &[
                    &format!("{}ms", self.lock_timeout.as_millis()),
                    &format!("{}ms", self.statement_timeout.as_millis()),
                ],
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(transaction)
    }

    async fn verify_catalog(&self, transaction: &tokio_postgres::Transaction<'_>) -> Result<()> {
        verify_catalog_identity_for_catalog(
            transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map(|_| ())
        .map_err(|_| Error::Unavailable)
    }

    /// One call to the migration-only maintenance function, bound to the
    /// expected package and activation. The function refuses a change when
    /// either, or the epoch, moved.
    async fn call(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        action: &str,
        projection: &str,
        epoch: Option<Uuid>,
        configured: Option<&ConfiguredScope>,
    ) -> Result<Value> {
        let activation =
            Uuid::parse_str(&self.expected.activation_id).map_err(|_| Error::Unavailable)?;
        Ok(transaction
            .query_one(
                MAINTENANCE,
                &[
                    &action,
                    &projection,
                    &epoch,
                    &self.expected.package_digest,
                    &activation,
                    &configured.map(|scope| scope.binding_digest.as_str()),
                    &configured.map(|scope| scope.grant_digest.as_str()),
                    &configured.map(|scope| scope.cache_ttl_seconds),
                ],
            )
            .await
            .map_err(lock_failure)?
            .get(0))
    }
}

fn lock_failure(error: tokio_postgres::Error) -> Error {
    if lock_wait_ended(&error) {
        Error::MigrationLockHeld
    } else {
        Error::Unavailable
    }
}

/// Inspect one indexed projection's scope. Diagnostics contain no connection
/// or configured values.
pub async fn inspect(path: &Path, projection: &str) -> Result<Value> {
    ExternalProjectionOperatorService::from_runtime_config(path)
        .await?
        .inspect(projection)
        .await
}

/// Withdraw one indexed projection's scope and purge its cached rows.
pub async fn withdraw(path: &Path, projection: &str) -> Result<Value> {
    ExternalProjectionOperatorService::from_runtime_config(path)
        .await?
        .withdraw(projection)
        .await
}

/// Rotate one indexed projection to a fresh epoch under the binding, grant and
/// cache lifetime its runtime configuration now asks for.
pub async fn rotate(path: &Path, projection: &str) -> Result<Value> {
    let (service, config, registry) = ExternalProjectionOperatorService::open(path).await?;
    service.require_indexed(projection)?;
    let configured = configured_scope(&registry, &config, projection)?;
    service.rotate(projection, &configured).await
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::*;
    use crate::postgres::external_projection::postgres_tests::{two_projection_project, Activated};
    use crate::postgres::external_view_query::tests::compile_project;
    use registry_platform_audit::AuditProfile;

    fn audit(fixture: &Activated) -> RegistryAudit {
        fixture.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x4e; 32].into())
                .expect("test owns a strong keyed audit profile"),
        )
    }

    fn operator(
        registry: &CompiledRegistry,
        fixture: &Activated,
    ) -> ExternalProjectionOperatorService {
        ExternalProjectionOperatorService::new_for_test(
            registry,
            fixture.expected.clone(),
            fixture.database.migration_config.clone(),
            fixture.database.migration_role.clone(),
            fixture.database.runtime_role.clone(),
            audit(fixture),
        )
    }

    #[test]
    fn rotation_takes_the_configured_binding_and_names_a_missing_one() {
        let sources = crate::external_source::tests::indexed_service(&[(
            "projection",
            "binding",
            "grant",
            45,
        )]);
        assert_eq!(
            scope_from_sources(&sources, "projection").unwrap(),
            ConfiguredScope {
                binding_digest: "binding".to_owned(),
                grant_digest: "grant".to_owned(),
                cache_ttl_seconds: 45,
            }
        );
        let Err(Error::BindingUnavailable { projection, reason }) =
            scope_from_sources(&sources, "other")
        else {
            panic!("a projection without a binding is refused");
        };
        assert_eq!(projection, "other");
        assert_eq!(reason, "no external source is bound to this projection");
    }

    #[tokio::test]
    async fn operators_inspect_withdraw_and_rotate_one_projection_under_audit() {
        let registry = compile_project(&two_projection_project());
        let fixture = Activated::new(&registry).await;
        let operator = operator(&registry, &fixture);

        let unbound = operator.inspect("projection").await.unwrap();
        assert!(unbound["epoch"].is_null());
        assert_eq!(unbound["active"], false);
        assert!(matches!(
            operator.inspect("missing").await,
            Err(Error::UnknownProjection(id)) if id == "missing"
        ));
        assert!(matches!(
            operator.withdraw("projection").await,
            Err(Error::NotBound(id)) if id == "projection"
        ));

        let first = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let other = fixture
            .bind(&registry, "other", "other-binding", "other-grant", 120)
            .await
            .unwrap();
        fixture.cache(&first).await;
        fixture.cache(&other).await;
        let inspected = operator.inspect("projection").await.unwrap();
        assert_eq!(inspected["epoch"], first.epoch.to_string());
        assert_eq!(inspected["active"], true);
        assert_eq!(inspected["bindingDigest"], "binding");
        assert_eq!(inspected["snapshotCounts"]["fresh"], 1);
        assert_eq!(inspected["packageDigest"], fixture.expected.package_digest);

        let withdrawn = operator.withdraw("projection").await.unwrap();
        assert_eq!(withdrawn["epoch"], first.epoch.to_string());
        assert_eq!(withdrawn["active"], false);
        assert_eq!(fixture.cached("projection", first.epoch).await, 0);
        assert!(
            !fixture
                .serves(&registry, "projection", "binding", "grant")
                .await
        );
        assert_eq!(fixture.cached("other", other.epoch).await, 1);
        assert!(
            fixture
                .serves(&registry, "other", "other-binding", "other-grant")
                .await
        );

        let configured = ConfiguredScope {
            binding_digest: "renewed-binding".to_owned(),
            grant_digest: "renewed-grant".to_owned(),
            cache_ttl_seconds: 30,
        };
        let rotated = operator.rotate("projection", &configured).await.unwrap();
        let epoch = Uuid::parse_str(rotated["epoch"].as_str().unwrap()).unwrap();
        assert_ne!(epoch, first.epoch);
        assert_eq!(rotated["active"], true);
        assert_eq!(rotated["bindingDigest"], "renewed-binding");
        assert_eq!(rotated["grantDigest"], "renewed-grant");
        assert_eq!(rotated["cacheTtlSeconds"], 30);
        assert!(
            fixture
                .serves(&registry, "projection", "renewed-binding", "renewed-grant")
                .await
        );
        let restarted = fixture
            .bind(
                &registry,
                "projection",
                "renewed-binding",
                "renewed-grant",
                30,
            )
            .await
            .unwrap();
        assert_eq!(restarted.epoch, epoch, "a restart keeps the rotated epoch");
        assert_eq!(fixture.cached("other", other.epoch).await, 1);

        let responses = fixture
            .database
            .audit_entries()
            .into_iter()
            .filter(|entry| {
                entry["schema"] == EXTERNAL_PROJECTION_AUDIT_SCHEMA && entry["phase"] == "response"
            })
            .map(|entry| {
                (
                    entry["record"]["action"].as_str().unwrap().to_owned(),
                    entry["record"]["outcome"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            responses,
            [
                ("withdraw".to_owned(), "failed".to_owned()),
                ("withdraw".to_owned(), "withdrawn".to_owned()),
                ("rotate".to_owned(), "rotated".to_owned()),
            ]
        );
        fixture.database.assert_every_audit_request_answered_once();
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn the_runtime_role_cannot_operate_a_projection_scope() {
        let registry = compile_project(&two_projection_project());
        let fixture = Activated::new(&registry).await;
        let bound = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let runtime = ExternalProjectionOperatorService::new_for_test(
            &registry,
            fixture.expected.clone(),
            fixture.database.runtime_config.clone(),
            fixture.database.migration_role.clone(),
            fixture.database.runtime_role.clone(),
            audit(&fixture),
        );
        assert!(matches!(
            runtime.withdraw("projection").await,
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            runtime.inspect("projection").await,
            Err(Error::Unavailable)
        ));
        assert!(
            fixture
                .serves(&registry, "projection", "binding", "grant")
                .await
        );
        assert_eq!(
            operator(&registry, &fixture)
                .inspect("projection")
                .await
                .unwrap()["epoch"],
            bound.epoch.to_string()
        );
        fixture.cleanup().await;
    }
}
