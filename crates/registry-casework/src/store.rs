use crate::{describe_secret_failure, DatabaseConfig};
use chrono::Utc;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_casework_core::{
    ActorContext, BootstrapDirectoryRequest, CaseworkRole, DirectoryMember, DirectoryResponse,
    IssuerPrincipal, TeamRecord,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio_postgres::Config as PgConfig;
use uuid::Uuid;
/// Every schema version, in the order it is applied. The baseline is
/// version [`BASELINE_SCHEMA_VERSION`], above every version an earlier
/// release applied; each later migration takes the next number.
pub(crate) const MIGRATIONS: [(i64, &str); 1] =
    [(200, include_str!("../migrations/0200_reviews.sql"))];
/// The baseline schema version. A ledger holding any version below it was
/// left by an earlier pre-1.0 release, which this release refuses by name:
/// version 100 is the v0.42.0 and v0.43.0 baseline, whose completion outbox
/// is not the shared dispatch shape this release reads.
pub(crate) const BASELINE_SCHEMA_VERSION: i64 = 200;
/// The newest schema version this release applies.
pub(crate) const SUPPORTED_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;
const _: () = assert!(
    versions_start_at_baseline_and_increase(&MIGRATIONS),
    "Casework migrations must start at BASELINE_SCHEMA_VERSION and strictly increase"
);

const fn versions_start_at_baseline_and_increase(migrations: &[(i64, &str)]) -> bool {
    if migrations.is_empty() || migrations[0].0 != BASELINE_SCHEMA_VERSION {
        return false;
    }
    let mut index = 1;
    while index < migrations.len() {
        if migrations[index].0 <= migrations[index - 1].0 {
            return false;
        }
        index += 1;
    }
    true
}
pub const MIGRATION_LOCK_KEY: i64 = 0x6361_7365_776f_726b;
pub(crate) const MAXIMUM_BOUNDED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
    audit: Option<crate::CaseworkAudit>,
    pub(crate) providers: std::sync::Arc<
        std::collections::BTreeMap<
            String,
            std::sync::Arc<dyn registry_casework_core::ReviewContextProvider>,
        >,
    >,
}
impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore").finish_non_exhaustive()
    }
}
/// Refuse a ledger this release cannot serve. A ledger holding any version
/// below the 1.0 baseline was left by a pre-1.0 release and is named first,
/// before the newer check: a fresh database is its only remedy.
pub(crate) fn refuse_unsupported_schema(applied: &[i64]) -> Result<(), StoreError> {
    if applied
        .iter()
        .any(|version| *version < BASELINE_SCHEMA_VERSION)
    {
        return Err(StoreError::Pre1_0Schema {
            versions: applied.to_vec(),
        });
    }
    match applied.iter().copied().max() {
        Some(found) if found > SUPPORTED_SCHEMA_VERSION => Err(StoreError::SchemaNewer {
            found,
            supported: SUPPORTED_SCHEMA_VERSION,
        }),
        _ => Ok(()),
    }
}

fn schema_versions(versions: &[i64]) -> String {
    versions
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn applied_schema(applied: Option<i64>) -> String {
    match applied {
        Some(version) => format!("its newest applied migration is version {version}"),
        None => "no migration has been applied".to_owned(),
    }
}

fn bound_database_connection(postgres: &mut PgConfig) {
    if postgres.get_connect_timeout().is_none() {
        postgres.connect_timeout(Duration::from_secs(5));
    }
    if postgres.get_keepalives_idle() == PgConfig::new().get_keepalives_idle() {
        postgres.keepalives_idle(Duration::from_secs(15));
    }
    if postgres.get_keepalives_interval().is_none() {
        postgres.keepalives_interval(Duration::from_secs(5));
    }
    if postgres.get_keepalives_retries().is_none() {
        postgres.keepalives_retries(3);
    }
    if postgres.get_tcp_user_timeout().is_none() {
        postgres.tcp_user_timeout(Duration::from_secs(30));
    }
}

pub(crate) async fn migrate_in(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<Vec<i64>, StoreError> {
    if let Some(refusal) = pending_migration_refusals(transaction, &[])
        .await?
        .into_iter()
        .next()
    {
        return Err(refusal);
    }
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS casework_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);",
        )
        .await?;
    let applied: Vec<i64> = transaction
        .query(
            "SELECT version FROM casework_schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .iter()
        .map(|row| row.try_get(0))
        .collect::<Result<_, _>>()?;
    refuse_unsupported_schema(&applied)?;
    let mut versions = Vec::new();
    for (version, migration) in MIGRATIONS {
        let applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=$1)",
                &[&version],
            )
            .await?
            .get(0);
        if applied {
            continue;
        }
        transaction.batch_execute(migration).await?;
        transaction
            .execute(
                "INSERT INTO casework_schema_migrations(version,applied_at) VALUES($1,now()) ON CONFLICT(version) DO NOTHING",
                &[&version],
            )
            .await?;
        versions.push(version);
    }
    Ok(versions)
}

/// A contract replacement never upgrades a database containing the retired model.
/// This checks table identity, not row counts, and preserves every existing byte.
pub(crate) async fn pending_migration_refusals(
    transaction: &tokio_postgres::Transaction<'_>,
    _applied: &[i64],
) -> Result<Vec<StoreError>, StoreError> {
    Ok(if retired_schema_present(transaction).await? {
        vec![StoreError::RetiredSchema]
    } else {
        Vec::new()
    })
}

async fn retired_schema_present(
    client: &impl tokio_postgres::GenericClient,
) -> Result<bool, StoreError> {
    Ok(client.query_one("SELECT to_regclass('casework_items') IS NOT NULL OR to_regclass('casework_subjects') IS NOT NULL OR to_regclass('casework_hosted_items') IS NOT NULL OR to_regclass('casework_attempts') IS NOT NULL",&[]).await?.get(0))
}

impl PostgresStore {
    pub fn connect_runtime(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.runtimeUrlRef",
            &config.runtime_url_ref,
        )
    }
    pub fn connect_migration(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.migrationUrlRef",
            &config.migration_url_ref,
        )
    }
    fn connect_reference(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
        field: &'static str,
        reference: &str,
    ) -> Result<Self, StoreError> {
        let protected = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(field, reference, &error))
        })?;
        let url = std::str::from_utf8(protected.expose_secret())
            .map_err(|_| StoreError::Configuration)?;
        let mut postgres = PgConfig::from_str(url).map_err(|_| StoreError::Configuration)?;
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(StoreError::Configuration);
        }
        bound_database_connection(&mut postgres);
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        #[cfg(feature = "postgres-test")]
        let manager = if config.test_only_plaintext {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
            Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
        } else {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        #[cfg(not(feature = "postgres-test"))]
        let manager = {
            if config.test_only_plaintext {
                return Err(StoreError::Configuration);
            }
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        let pool = Pool::builder(manager)
            .max_size(32)
            .wait_timeout(Some(Duration::from_secs(5)))
            .create_timeout(Some(Duration::from_secs(5)))
            .recycle_timeout(Some(Duration::from_secs(5)))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| StoreError::Configuration)?;
        Ok(Self {
            pool,
            audit: None,
            providers: Default::default(),
        })
    }
    pub fn with_audit(mut self, audit: crate::CaseworkAudit) -> Self {
        self.audit = Some(audit);
        self
    }
    pub async fn audit_ready(&self) -> bool {
        match &self.audit {
            Some(audit) => audit.ready().await,
            None => false,
        }
    }
    pub(crate) async fn begin_background_audit(
        &self,
    ) -> Result<crate::audit::AuditOperation, StoreError> {
        self.audit
            .as_ref()
            .ok_or(StoreError::AuditUnavailable)?
            .begin_background()
            .await
            .map(|operation| operation.with_read_back(self.pool.clone()))
    }
    pub(crate) async fn begin_audit(
        &self,
        request: Value,
    ) -> Result<crate::audit::AuditOperation, StoreError> {
        self.audit
            .as_ref()
            .ok_or(StoreError::AuditUnavailable)?
            .begin(request)
            .await
            .map(|operation| operation.with_read_back(self.pool.clone()))
    }
    pub(crate) async fn begin_audit_with_schema(
        &self,
        schema: &str,
        request: Value,
    ) -> Result<crate::audit::AuditOperation, StoreError> {
        self.audit
            .as_ref()
            .ok_or(StoreError::AuditUnavailable)?
            .begin_with_schema(schema, request)
            .await
            .map(|operation| operation.with_read_back(self.pool.clone()))
    }
    pub(crate) fn audit_identifiers(
        &self,
    ) -> Result<registry_platform_audit::AuditKeyHasher, StoreError> {
        self.audit
            .as_ref()
            .map(crate::CaseworkAudit::identifiers)
            .ok_or(StoreError::AuditUnavailable)
    }
    pub(crate) async fn begin_audit_for(
        &self,
        actor: Option<&ActorContext>,
        event: &str,
        identifiers: Value,
    ) -> Result<crate::audit::AuditOperation, StoreError> {
        match actor {
            Some(actor) => {
                self.begin_audit(crate::audit::request_record(
                    event,
                    Some(actor),
                    &actor.profile_id,
                    identifiers,
                ))
                .await
            }
            None => self.begin_background_audit().await,
        }
    }
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;
        migrate_in(&transaction).await?;
        transaction.commit().await?;
        Ok(())
    }
    pub async fn ready(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        if let Some(schema) = crate::activation::unreadable_ledger(&**client).await? {
            return Err(StoreError::LedgerUnreadable { schema });
        }
        // A retired schema needs a fresh database whatever its ledger says,
        // so it is named before any version comparison.
        let connection: &tokio_postgres::Client = &client;
        if retired_schema_present(connection).await? {
            return Err(StoreError::RetiredSchema);
        }
        let ledger_exists: bool = client
            .query_one(
                "SELECT to_regclass('casework_schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        if !ledger_exists {
            return Err(StoreError::SchemaNotCurrent {
                applied: None,
                required: SUPPORTED_SCHEMA_VERSION,
            });
        }
        let applied = client
            .query(
                "SELECT version FROM casework_schema_migrations ORDER BY version",
                &[],
            )
            .await?;
        refuse_unsupported_schema(
            &applied
                .iter()
                .map(|row| row.try_get::<_, i64>(0))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let schema_is_current = applied.len() == MIGRATIONS.len()
            && applied
                .iter()
                .zip(MIGRATIONS.iter())
                .all(|(row, (expected, _))| {
                    row.try_get::<_, i64>(0)
                        .is_ok_and(|version| version == *expected)
                });
        if schema_is_current {
            Ok(())
        } else {
            Err(StoreError::SchemaNotCurrent {
                applied: applied
                    .last()
                    .map(|row| row.try_get::<_, i64>(0))
                    .transpose()?,
                required: SUPPORTED_SCHEMA_VERSION,
            })
        }
    }
    pub async fn directory_ready(&self, expected_queue_ids: &[String]) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one(
                "SELECT cardinality($1::text[]) > 0 AND NOT EXISTS(SELECT 1 FROM unnest($1::text[]) expected(queue_id) WHERE NOT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_teams t ON t.team_id=q.team_id WHERE q.queue_id=expected.queue_id))",
                &[&expected_queue_ids],
            )
            .await?
            .get(0))
    }
    pub(crate) async fn client(&self) -> Result<deadpool_postgres::Client, StoreError> {
        self.pool.get().await.map_err(|_| StoreError::Unavailable)
    }
    pub async fn bootstrap_directory(
        &self,
        actor: &ActorContext,
        expected_revision: i64,
        request: &BootstrapDirectoryRequest,
        idempotency_key: &str,
    ) -> Result<i64, StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        let request_hash = request_hash(request)?;
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "directory-bootstrapped",
                Some(actor),
                &actor.profile_id,
                json!({"teamId": request.team_id, "queueId": request.queue_id}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        if let Some(response) = idempotent_response(
            &transaction,
            actor,
            "directory.bootstrap",
            "directory",
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            let revision = response
                .get("revision")
                .and_then(Value::as_i64)
                .ok_or(StoreError::Corrupt)?;
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(revision);
        }
        let actual: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton = true FOR UPDATE",
                &[],
            )
            .await?
            .get(0);
        if actual != expected_revision {
            return Err(StoreError::Conflict);
        }
        let next = actual.checked_add(1).ok_or(StoreError::Corrupt)?;
        transaction
            .execute(
                "INSERT INTO casework_teams(team_id, revision) VALUES ($1,$2)",
                &[&request.team_id, &next],
            )
            .await
            .map_err(map_unique_conflict)?;
        for principal in &request.staff {
            insert_membership(&transaction, &request.team_id, principal, "staff").await?;
        }
        for principal in &request.supervisors {
            insert_membership(&transaction, &request.team_id, principal, "supervisor").await?;
        }
        transaction
            .execute(
                "INSERT INTO casework_queue_service(queue_id, team_id, revision) VALUES ($1,$2,$3)",
                &[&request.queue_id, &request.team_id, &next],
            )
            .await
            .map_err(map_unique_conflict)?;
        transaction
            .execute(
                "UPDATE casework_meta SET directory_revision=$1 WHERE singleton=true",
                &[&next],
            )
            .await?;
        directory_snapshot(&transaction, next).await?;
        let event_id = Uuid::new_v4();
        let now = Utc::now();
        let detail = json!({"teamId":request.team_id,"queueId":request.queue_id});
        transaction.execute(
            "INSERT INTO casework_directory_events(event_id,directory_revision,event_kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,'directory-bootstrapped',$3,$4,$5,$6,$7)",
            &[&event_id,&next,&now,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&detail],
        ).await?;
        audit.record(
            event_id,
            json!({
                "event":"casework.directory-bootstrapped","directoryRevision":next,
                "actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},
                "profileId":actor.profile_id,"teamId":request.team_id,"queueId":request.queue_id
            }),
        )?;
        let response = json!({"revision":next});
        insert_idempotency(
            &transaction,
            actor,
            "directory.bootstrap",
            "directory",
            idempotency_key,
            &request_hash,
            &response,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(next)
    }
    pub async fn directory(
        &self,
        actor: &ActorContext,
    ) -> Result<(i64, Vec<TeamRecord>), StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let revision: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?
            .get(0);
        let teams = directory_snapshot(&transaction, revision).await?;
        transaction.commit().await?;
        Ok((revision, teams))
    }
    pub async fn served_queues(&self, actor: &ActorContext) -> Result<Vec<String>, StoreError> {
        let membership_kind = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(StoreError::Forbidden);
            }
        };
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT DISTINCT q.queue_id FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE m.issuer=$1 AND m.subject=$2 AND m.membership_kind=$3 ORDER BY q.queue_id",
                &[&actor.principal.issuer, &actor.principal.subject, &membership_kind],
            )
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }
}

pub(crate) async fn directory_snapshot(
    transaction: &tokio_postgres::Transaction<'_>,
    revision: i64,
) -> Result<Vec<TeamRecord>, StoreError> {
    let empty = DirectoryResponse {
        // Absences and calendar changes also advance this revision. Reserve
        // its widest encoding so an accepted directory remains readable.
        revision: i64::MAX,
        teams: Vec::new(),
    };
    let mut serialized_bytes = serde_json::to_vec(&empty)?.len();
    let mut teams = Vec::new();
    let mut after = String::new();
    loop {
        let rows = transaction
            .query(
                "SELECT team_id,revision FROM casework_teams WHERE team_id>$1 ORDER BY team_id LIMIT 100",
                &[&after],
            )
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let team_id: String = row.get(0);
            let members = membership_list(transaction, &team_id, "staff").await?;
            let supervisors = membership_list(transaction, &team_id, "supervisor").await?;
            let served_queues = transaction.query(
                "SELECT queue_id FROM casework_queue_service WHERE team_id=$1 ORDER BY queue_id", &[&team_id]
            ).await?.into_iter().map(|row| row.get(0)).collect();
            let team = TeamRecord {
                id: team_id.clone(),
                members,
                supervisors,
                served_queues,
                revision: row.get(1),
            };
            serialized_bytes = serialized_bytes
                .checked_add(serde_json::to_vec(&team)?.len())
                .and_then(|size| size.checked_add(usize::from(!teams.is_empty())))
                .ok_or(StoreError::Corrupt)?;
            if serialized_bytes > MAXIMUM_BOUNDED_RESPONSE_BYTES {
                return Err(StoreError::Invalid);
            }
            after = team_id;
            teams.push(team);
        }
    }
    let response = DirectoryResponse { revision, teams };
    if serde_json::to_vec(&response)?.len() > MAXIMUM_BOUNDED_RESPONSE_BYTES {
        return Err(StoreError::Invalid);
    }
    Ok(response.teams)
}

async fn membership_list(
    transaction: &tokio_postgres::Transaction<'_>,
    team_id: &str,
    kind: &str,
) -> Result<Vec<DirectoryMember>, StoreError> {
    Ok(transaction.query("SELECT issuer,subject,display_name FROM casework_memberships WHERE team_id=$1 AND membership_kind=$2 ORDER BY issuer,subject", &[&team_id,&kind]).await?.into_iter().map(|row|DirectoryMember{issuer:row.get(0),subject:row.get(1),display_name:row.get(2)}).collect())
}

async fn insert_membership(
    transaction: &tokio_postgres::Transaction<'_>,
    team_id: &str,
    principal: &IssuerPrincipal,
    kind: &str,
) -> Result<(), StoreError> {
    transaction.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES($1,$2,$3,$4)",&[&team_id,&principal.issuer,&principal.subject,&kind]).await.map_err(map_unique_conflict)?;
    Ok(())
}

async fn idempotent_response(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
) -> Result<Option<Value>, StoreError> {
    if key.is_empty() || key.len() > 256 {
        return Err(StoreError::Invalid);
    }
    let row=transaction.query_opt("SELECT request_hash,response FROM casework_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation=$4 AND resource=$5 AND idempotency_key=$6 FOR UPDATE", &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key]).await?;
    if let Some(row) = row {
        if row.get::<_, String>(0) != hash {
            return Err(StoreError::IdempotencyConflict);
        }
        return row
            .get::<_, Option<Value>>(1)
            .ok_or(StoreError::IdempotencyExpired)
            .map(Some);
    }
    Ok(None)
}

async fn insert_idempotency(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
    response: &Value,
) -> Result<(), StoreError> {
    transaction.execute("INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key,&hash,&response,&Utc::now()]).await.map_err(map_unique_conflict)?;
    Ok(())
}

fn request_hash<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    Ok(hash_bytes(&serde_json::to_vec(value)?))
}

fn map_unique_conflict(error: tokio_postgres::Error) -> StoreError {
    if error
        .as_db_error()
        .is_some_and(|e| e.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    {
        StoreError::Conflict
    } else {
        StoreError::Postgres(error)
    }
}

fn tls_connector(
    config: &DatabaseConfig,
    secrets: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(StoreError::Configuration);
    }
    if let Some(reference) = &config.trusted_root_certificate_ref {
        let certificate = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(
                "database.trustedRootCertificateRef",
                reference,
                &error,
            ))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        let mut count = 0usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.expose_secret())
        {
            roots
                .add(certificate.map_err(|_| StoreError::Configuration)?)
                .map_err(|_| StoreError::Configuration)?;
            count += 1;
        }
        if count == 0 {
            return Err(StoreError::Configuration);
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| StoreError::Configuration)
    }
}

fn violated_constraint(error: &tokio_postgres::Error) -> String {
    error
        .as_db_error()
        .and_then(|error| error.constraint())
        .map(|constraint| format!(" (constraint {constraint})"))
        .unwrap_or_default()
}
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("this release requires a fresh review-only database; the configured database contains a retired Casework schema. Preserve it with the release that wrote it and configure a fresh database before applying this package")]
    RetiredSchema,
    #[error("PostgreSQL 17 or newer is required; upgrade the database server before activating or serving a package")]
    UnsupportedPostgres,
    #[error("the Casework database configuration is invalid")]
    Configuration,
    #[error("the Casework database configuration is invalid: {0}")]
    SecretConfiguration(String),
    #[error("the Casework database is unavailable")]
    Unavailable,
    #[error("the Casework audit destination is unavailable")]
    AuditUnavailable,
    #[error("the requested resource was not found")]
    NotFound,
    #[error("the caller is not authorized for this operation")]
    Forbidden,
    #[error("the expected revision is no longer current")]
    Conflict,
    #[error("the review task is already claimed")]
    AlreadyClaimed,
    #[error("the caller does not hold the review task")]
    NotHolder,
    #[error("the idempotency key was already used with different input")]
    IdempotencyConflict,
    #[error("the stored idempotent response has expired")]
    IdempotencyExpired,
    #[error(transparent)]
    Absence(#[from] registry_casework_core::AbsenceError),
    #[error("the request is invalid")]
    Invalid,
    #[error(transparent)]
    ReviewValidation(#[from] registry_casework_core::ReviewValidationError),
    #[error("the pagination cursor is invalid")]
    CursorInvalid,
    #[error("the pagination cursor has expired")]
    CursorExpired,
    #[error("stored Casework data is invalid")]
    Corrupt,
    #[error(
        "the Casework database schema version {found} is newer than this binary supports ({supported}); run a casework release that supports it"
    )]
    SchemaNewer { found: i64, supported: i64 },
    #[error(
        "the Casework database uses a pre-1.0 schema (versions {}); this release supports fresh installs only. Create a fresh database and apply the package",
        schema_versions(versions)
    )]
    Pre1_0Schema { versions: Vec<i64> },
    #[error(
        "the Casework runtime role cannot read the activation ledger in schema {schema}; run `caseworkctl apply --runtime-config FILE` to grant the runtime role its privileges, then rerun `caseworkctl plan --runtime-config FILE`"
    )]
    LedgerUnreadable { schema: String },
    #[error(
        "the Casework database schema is not current: {}, and this binary requires version {required}; run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`",
        applied_schema(*.applied)
    )]
    SchemaNotCurrent { applied: Option<i64>, required: i64 },
    #[error("the Casework database operation failed{}", violated_constraint(.0))]
    Postgres(#[from] tokio_postgres::Error),
    #[error("Casework serialization failed")]
    Json(#[from] serde_json::Error),
}

pub(crate) async fn pinned_work_inventory_in(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<crate::pinned_work::PinnedWorkInventory, StoreError> {
    let rows=tx.query("SELECT policy_snapshot,producer_id,source_namespace,active_stage_index,count(*) FROM casework_review_requests WHERE lifecycle='reviewing' GROUP BY policy_snapshot,producer_id,source_namespace,active_stage_index",&[]).await?;
    Ok(crate::pinned_work::PinnedWorkInventory {
        reviews: rows
            .into_iter()
            .map(|row| {
                Ok(crate::pinned_work::PinnedReviewGroup {
                    policy: serde_json::from_value(row.get(0))?,
                    producer_id: row.get(1),
                    source_namespace: row.get(2),
                    active_stage_index: usize::try_from(row.get::<_, i32>(3))
                        .map_err(|_| StoreError::Corrupt)?,
                    reviews: u64::try_from(row.get::<_, i64>(4))
                        .map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?,
    })
}

impl PostgresStore {
    pub(crate) fn with_context_providers(
        mut self,
        providers: std::sync::Arc<
            std::collections::BTreeMap<
                String,
                std::sync::Arc<dyn registry_casework_core::ReviewContextProvider>,
            >,
        >,
    ) -> Self {
        self.providers = providers;
        self
    }
}

fn hash_bytes(value: &[u8]) -> String {
    registry_platform_config::sha256_uri(value)
        .trim_start_matches("sha256:")
        .to_owned()
}

#[cfg(test)]
mod schema_version_tests {
    use super::*;

    #[test]
    fn the_baseline_is_version_200_and_later_versions_increase() {
        assert_eq!(BASELINE_SCHEMA_VERSION, 200);
        assert!(versions_start_at_baseline_and_increase(&MIGRATIONS));
        assert!(versions_start_at_baseline_and_increase(&[
            (200, ""),
            (201, "")
        ]));
        assert!(!versions_start_at_baseline_and_increase(&[]));
        assert!(!versions_start_at_baseline_and_increase(&[(1, "")]));
        assert!(!versions_start_at_baseline_and_increase(&[(100, "")]));
        assert!(!versions_start_at_baseline_and_increase(&[
            (200, ""),
            (200, "")
        ]));
    }

    #[test]
    fn every_ledger_below_the_baseline_is_a_named_pre_1_0_refusal() {
        let beta_ledgers: [Vec<i64>; 5] =
            [vec![1], vec![1, 2], (1..=13).collect(), vec![19], vec![100]];
        for applied in beta_ledgers {
            match refuse_unsupported_schema(&applied) {
                Err(refusal @ StoreError::Pre1_0Schema { .. }) => {
                    let message = refusal.to_string();
                    assert!(
                        message.starts_with("the Casework database uses a pre-1.0 schema (versions ")
                            && message.ends_with(
                                "this release supports fresh installs only. Create a fresh database and apply the package"
                            ),
                        "{message}"
                    );
                }
                other => panic!("{applied:?} must be a pre-1.0 refusal: {other:?}"),
            }
        }
        assert!(refuse_unsupported_schema(&[]).is_ok());
        assert!(refuse_unsupported_schema(&[200]).is_ok());
        assert!(matches!(
            refuse_unsupported_schema(&[200, 201]),
            Err(StoreError::SchemaNewer {
                found: 201,
                supported: 200
            })
        ));
    }
}
