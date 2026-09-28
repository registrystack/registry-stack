// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

use crate::generated_ddl::POSTGIS_EXTENSION_SCHEMA;
use crate::physical_names::hex_prefix;

use super::catalog::MANAGED_SCHEMAS;
use super::{PostgresKernelError, Result};

const MIN_POSTGIS_MAJOR: u32 = 3;
const MIN_POSTGIS_MINOR: u32 = 5;

/// A validated PostgreSQL identifier used only for governed provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlIdentifier(String);

impl SqlIdentifier {
    pub fn parse(value: &str) -> Result<Self> {
        let mut characters = value.chars();
        let valid_start = characters
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_lowercase());
        let valid_rest = characters.all(|character| {
            character == '_' || character.is_ascii_lowercase() || character.is_ascii_digit()
        });
        if !valid_start || !valid_rest || value.len() > 63 {
            return Err(PostgresKernelError::Configuration(
                "PostgreSQL identifier is outside the governed identifier grammar",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn quoted(&self) -> QuotedIdentifier<'_> {
        QuotedIdentifier(self)
    }
}

pub(crate) struct QuotedIdentifier<'a>(&'a SqlIdentifier);

impl fmt::Display for QuotedIdentifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "\"{}\"", self.0.as_str())
    }
}

/// The runtime grantee of a least-privilege `REVOKE`.
///
/// In single-role mode the connected migration role is also the runtime role.
/// It owns every managed object, so a `REVOKE` naming it would strip the owner
/// privileges that later migration statements rely on. Installers therefore
/// revoke from `PUBLIC` alone in that mode, and their grants to the runtime
/// role change nothing for the owner.
pub struct RuntimeRevoke<'a>(Option<&'a SqlIdentifier>);

impl<'a> RuntimeRevoke<'a> {
    pub async fn detect(
        client: &impl GenericClient,
        runtime_role: &'a SqlIdentifier,
    ) -> std::result::Result<Self, tokio_postgres::Error> {
        let current: String = client.query_one("SELECT current_user", &[]).await?.get(0);
        Ok(Self(
            (current != runtime_role.as_str()).then_some(runtime_role),
        ))
    }

    /// The grantee list `PUBLIC, "runtime"`, or `PUBLIC` in single-role mode.
    pub fn with_public(&self) -> String {
        match self.0 {
            Some(role) => format!("PUBLIC, {}", role.quoted()),
            None => "PUBLIC".to_owned(),
        }
    }

    /// A statement revoking every privilege on `objects` from the runtime
    /// role, or nothing in single-role mode.
    pub fn revoke_all_on(&self, objects: &str) -> String {
        match self.0 {
            Some(role) => format!("REVOKE ALL ON {objects} FROM {};", role.quoted()),
            None => String::new(),
        }
    }
}

/// Admin-only provisioning of the managed schemas.
pub async fn provision_managed_schemas(
    admin: &impl GenericClient,
    migration_role: &SqlIdentifier,
) -> Result<()> {
    for schema in [
        "registry_internal",
        "registry_data",
        "registry_source",
        "registry_derived",
        "registry_context",
    ] {
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema} AUTHORIZATION {};\n\
                 REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;",
                migration_role.quoted(),
            ))
            .await?;
    }
    Ok(())
}

pub fn spatial_bbox_role(runtime_role: &SqlIdentifier) -> SqlIdentifier {
    let candidate = format!("{}__spatial_bbox", runtime_role.as_str());
    if candidate.len() <= 63 {
        return SqlIdentifier::parse(&candidate)
            .expect("derived bbox role follows identifier grammar");
    }
    let digest =
        Sha256::digest(format!("breg/spatial-bbox-role/v1:{}", runtime_role.as_str()).as_bytes());
    SqlIdentifier::parse(&format!("breg_bbox_{}", hex_prefix(&digest, 8)))
        .expect("hashed bbox role follows identifier grammar")
}

/// Admin-only provisioning for one spatial runtime role. The migration role must
/// never own or create PostGIS objects; it only verifies that this bootstrap
/// happened before applying a spatial package.
pub async fn provision_postgis_prerequisites(
    admin: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<SqlIdentifier> {
    verify_postgres_16_or_newer(admin).await?;
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS {POSTGIS_EXTENSION_SCHEMA};\n\
             REVOKE ALL ON SCHEMA {POSTGIS_EXTENSION_SCHEMA} FROM PUBLIC;\n\
             CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA {POSTGIS_EXTENSION_SCHEMA};\n\
             GRANT USAGE ON SCHEMA {POSTGIS_EXTENSION_SCHEMA} TO {}, {};",
            migration_role.quoted(),
            runtime_role.quoted(),
        ))
        .await?;
    let bbox_role = provision_spatial_bbox_role(admin, migration_role, runtime_role).await?;
    Ok(bbox_role)
}

/// Admin-only provisioning of the no-login bbox role that owns spatial
/// candidate views. The migration role may SET it only to create, replace, or
/// drop those views; runtime must never be a member.
pub async fn provision_spatial_bbox_role(
    admin: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<SqlIdentifier> {
    verify_postgres_16_or_newer(admin).await?;
    let bbox_role = spatial_bbox_role(runtime_role);
    admin
        .batch_execute(&format!(
            "DO $breg_spatial$\n\
             BEGIN\n\
                 IF NOT EXISTS (\n\
                     SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{}'\n\
                 ) THEN\n\
                     CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;\n\
                 END IF;\n\
             END;\n\
             $breg_spatial$;\n\
             GRANT {} TO {} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n\
             GRANT USAGE ON SCHEMA {POSTGIS_EXTENSION_SCHEMA} TO {};",
            bbox_role.as_str(),
            bbox_role.quoted(),
            bbox_role.quoted(),
            migration_role.quoted(),
            bbox_role.quoted(),
        ))
        .await?;
    Ok(bbox_role)
}

pub async fn verify_postgis(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    verify_postgres_16_or_newer(client).await?;
    let bbox_role = spatial_bbox_role(runtime_role);
    verify_postgis_spatial_bbox_role(client, migration_role, runtime_role, &bbox_role).await?;
    let installed = client
        .query_opt(
            "WITH postgis AS (
                 SELECT e.extversion, e.extowner, n.oid AS namespace_oid, n.nspname, n.nspowner,
                        schema_owner.rolname AS schema_owner_name,
                        extension_owner.rolname AS extension_owner_name,
                        COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner)) AS acl
                   FROM pg_catalog.pg_extension e
                   JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
                   JOIN pg_catalog.pg_roles schema_owner ON schema_owner.oid = n.nspowner
                   JOIN pg_catalog.pg_roles extension_owner ON extension_owner.oid = e.extowner
                  WHERE e.extname = 'postgis'
             ), acl AS (
                 SELECT postgis.*, grant_acl.grantee, grant_acl.privilege_type
                   FROM postgis
                   CROSS JOIN LATERAL pg_catalog.aclexplode(postgis.acl) AS grant_acl
             )
             SELECT extversion,
                    nspname,
                    schema_owner_name,
                    EXISTS (SELECT 1 FROM acl WHERE grantee = 0 AND privilege_type = 'CREATE'),
                    pg_catalog.has_schema_privilege($1, nspname, 'CREATE'),
                    pg_catalog.has_schema_privilege($2, nspname, 'CREATE'),
                    pg_catalog.has_schema_privilege($3, nspname, 'CREATE'),
                    EXISTS (
                        SELECT 1
                          FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $3)
                           AND privilege_type = 'USAGE'
                    ),
                    EXISTS (
                        SELECT 1
                          FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
                           AND privilege_type = 'USAGE'
                    ),
                    EXISTS (
                        SELECT 1
                          FROM acl
                         WHERE grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $2)
                           AND privilege_type = 'USAGE'
                    ),
                    schema_owner_name = $1,
                    schema_owner_name = $2,
                    schema_owner_name = $3,
                    extension_owner_name = $1,
                    extension_owner_name = $2,
                    extension_owner_name = $3,
                    pg_catalog.pg_has_role($1, extowner, 'MEMBER'),
                    pg_catalog.pg_has_role($2, extowner, 'MEMBER'),
                    pg_catalog.pg_has_role($3, extowner, 'MEMBER')
               FROM postgis",
            &[
                &migration_role.as_str(),
                &runtime_role.as_str(),
                &bbox_role.as_str(),
            ],
        )
        .await?;
    let Some(row) = installed else {
        return Err(PostgresKernelError::CatalogInvariant(
            "administrator-installed PostGIS is required",
        ));
    };
    let version: String = row.get(0);
    if !postgis_version_supported(&version)
        || row.get::<_, String>(1) != POSTGIS_EXTENSION_SCHEMA
        || (3..=6).any(|index| row.get::<_, bool>(index))
        || !row.get::<_, bool>(7)
        || !row.get::<_, bool>(8)
        || !row.get::<_, bool>(9)
        || (10..=18).any(|index| row.get::<_, bool>(index))
    {
        return Err(PostgresKernelError::CatalogInvariant(
            "administrator-installed PostGIS does not match the governed prerequisite",
        ));
    }
    verify_required_postgis_symbols(client).await
}

async fn verify_postgis_spatial_bbox_role(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    bbox_role: &SqlIdentifier,
) -> Result<()> {
    verify_spatial_bbox_role_bits(client, bbox_role).await?;
    let row = client
        .query_opt(
            "SELECT pg_catalog.pg_has_role($1, bbox.oid, 'MEMBER'),
                    m.inherit_option,
                    m.set_option,
                    m.admin_option,
                    pg_catalog.pg_has_role(bbox.oid, runtime.oid, 'MEMBER'),
                    pg_catalog.pg_has_role($2, bbox.oid, 'MEMBER'),
                    EXISTS (
                        SELECT 1
                          FROM pg_catalog.pg_auth_members upstream
                         WHERE upstream.member = bbox.oid
                    )
               FROM pg_catalog.pg_roles migration
               JOIN pg_catalog.pg_roles runtime ON runtime.rolname = $2
               JOIN pg_catalog.pg_roles bbox ON bbox.rolname = $3
               JOIN pg_catalog.pg_auth_members m
                 ON m.member = migration.oid AND m.roleid = bbox.oid
              WHERE migration.rolname = $1",
            &[
                &migration_role.as_str(),
                &runtime_role.as_str(),
                &bbox_role.as_str(),
            ],
        )
        .await?;
    let Some(row) = row else {
        return Err(PostgresKernelError::RoleInvariant(
            "spatial bbox role membership is incomplete or invalid",
        ));
    };
    // In single-role mode the runtime role is the migration role, which holds
    // the bbox role for SET ROLE, so only split-role mode refuses that membership.
    let valid_membership = row.get::<_, bool>(0)
        && !row.get::<_, bool>(1)
        && row.get::<_, bool>(2)
        && !row.get::<_, bool>(3)
        && !row.get::<_, bool>(4)
        && (migration_role == runtime_role || !row.get::<_, bool>(5))
        && !row.get::<_, bool>(6);
    if !valid_membership {
        return Err(PostgresKernelError::RoleInvariant(
            "spatial bbox role membership is incomplete or invalid",
        ));
    }
    Ok(())
}

async fn verify_spatial_bbox_role_bits(
    client: &impl GenericClient,
    bbox_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_opt(
            "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit
               FROM pg_catalog.pg_roles
              WHERE rolname = $1",
            &[&bbox_role.as_str()],
        )
        .await?;
    let Some(row) = row else {
        return Err(PostgresKernelError::RoleInvariant(
            "spatial bbox role membership is incomplete or invalid",
        ));
    };
    if (0..=5).any(|index| row.get::<_, bool>(index)) {
        return Err(PostgresKernelError::RoleInvariant(
            "spatial bbox role membership is incomplete or invalid",
        ));
    }
    Ok(())
}

async fn verify_required_postgis_symbols(client: &impl GenericClient) -> Result<()> {
    let row = client
        .query_one(
            "SELECT to_regtype('registry_spatial_ext.geometry') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makepoint(double precision,double precision)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_setsrid(registry_spatial_ext.geometry,integer)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makeline(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_makeenvelope(double precision,double precision,double precision,double precision,integer)') IS NOT NULL,
                    to_regprocedure('registry_spatial_ext.st_intersects(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL,
                    to_regoperator('registry_spatial_ext.&&(registry_spatial_ext.geometry,registry_spatial_ext.geometry)') IS NOT NULL",
            &[],
        )
        .await?;
    if (0..=6).any(|index| !row.get::<_, bool>(index)) {
        return Err(PostgresKernelError::CatalogInvariant(
            "administrator-installed PostGIS does not expose the required spatial symbols",
        ));
    }
    Ok(())
}

fn postgis_version_supported(version: &str) -> bool {
    let mut parts = version.split('.');
    let Some(major) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    let Some(minor) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    major > MIN_POSTGIS_MAJOR || (major == MIN_POSTGIS_MAJOR && minor >= MIN_POSTGIS_MINOR)
}

async fn verify_postgres_16_or_newer(client: &impl GenericClient) -> Result<()> {
    let version_num: String = client
        .query_one("SELECT current_setting('server_version_num')", &[])
        .await?
        .get(0);
    let version_num = version_num.parse::<u32>().map_err(|_| {
        PostgresKernelError::Configuration(
            "PostgreSQL 16 or newer is required for spatial bbox roles",
        )
    })?;
    if version_num < 160_000 {
        return Err(PostgresKernelError::Configuration(
            "PostgreSQL 16 or newer is required for spatial bbox roles",
        ));
    }
    Ok(())
}

pub async fn verify_btree_gist(client: &impl GenericClient) -> Result<()> {
    let installed = client
        .query_opt(
            "SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'btree_gist'",
            &[],
        )
        .await?
        .is_some();
    if !installed {
        return Err(PostgresKernelError::CatalogInvariant(
            "administrator-installed btree_gist is required",
        ));
    }
    Ok(())
}

pub async fn verify_migration_role(
    client: &impl GenericClient,
    expected_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_one(
            "SELECT current_user,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    has_database_privilege(current_user, current_database(), 'CREATE')
             FROM pg_catalog.pg_roles
             WHERE rolname = current_user",
            &[],
        )
        .await?;
    let role: String = row.get(0);
    if role != expected_role.as_str() {
        return Err(PostgresKernelError::RoleInvariant(
            "migration connection uses the wrong role",
        ));
    }
    let forbidden = (1..=5).any(|index| row.get::<_, bool>(index));
    if forbidden {
        return Err(PostgresKernelError::RoleInvariant(
            "migration role has database-level administrative authority",
        ));
    }
    verify_schema_owner(client, expected_role).await
}

pub async fn verify_runtime_role(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_one(
            "SELECT current_user,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    current_user = $1,
                    pg_has_role(current_user, $1, 'MEMBER'),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'registry_internal', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_data', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_source', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_derived', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_context', 'CREATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname IN (
                            'registry_internal',
                            'registry_data',
                            'registry_source',
                            'registry_derived',
                            'registry_context'
                        )
                          AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    )
             FROM pg_catalog.pg_roles
             WHERE rolname = current_user",
            &[&migration_role.as_str()],
        )
        .await?;
    let forbidden = (1..=13).any(|index| row.get::<_, bool>(index));
    if forbidden {
        return Err(PostgresKernelError::RoleInvariant(
            "runtime role has ownership, bypass, or DDL authority",
        ));
    }
    let permissions = client
        .query_one(
            "SELECT
                 has_table_privilege(current_user, 'registry_internal.registry_state', 'SELECT'),
                 has_table_privilege(current_user, 'registry_internal.registry_state', 'INSERT'),
                 has_table_privilege(current_user, 'registry_internal.registry_state', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_internal.registry_state', 'DELETE'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'SELECT'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'INSERT'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'DELETE'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'TRUNCATE'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'REFERENCES'),
                 has_table_privilege(current_user, 'registry_data.kernel_records', 'TRIGGER')",
            &[],
        )
        .await?;
    let required = [0, 4, 5, 6, 7]
        .into_iter()
        .all(|index| permissions.get::<_, bool>(index));
    let denied = [1, 2, 3, 8, 9, 10]
        .into_iter()
        .all(|index| !permissions.get::<_, bool>(index));
    if !required || !denied {
        return Err(PostgresKernelError::RoleInvariant(
            "runtime role has an unexpected managed-table privilege set",
        ));
    }
    Ok(())
}

/// One way a split-role runtime role could write the activation ledger or the
/// registry state, with the statement that removes it.
///
/// Threat: an owner of a table apply touches can add a deferred constraint
/// trigger that runs as the migration role when an apply commits and writes
/// the ledger; a superuser, a member of the migration role, of another
/// superuser role, or of `pg_write_all_data`, a holder of CREATE on a
/// registry schema or TRIGGER on a registry table, or a holder of a write
/// privilege on the ledger or the state can write it directly or through an
/// object it adds. Enforcement: split-role apply and startup call
/// [`find_runtime_write_authority`] before any other database check and
/// refuse the first finding by name. Every fix names its grantee exactly, so
/// a privilege PUBLIC holds names `FROM PUBLIC`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeWriteAuthority {
    Superuser {
        runtime: String,
    },
    MigrationRoleMember {
        runtime: String,
        migration: String,
    },
    /// A member of a superuser role or of `pg_write_all_data`, either of
    /// which writes every table.
    PrivilegedRoleMember {
        runtime: String,
        role: String,
    },
    /// The runtime role owns a registry object. Reassigning ownership strips
    /// the runtime grants the object carried, so the fix ends with the apply
    /// that reissues them.
    Owner {
        object: String,
        runtime: String,
        migration: String,
    },
    OwnerMember {
        object: String,
        owner: String,
        runtime: String,
    },
    Privilege {
        grantee: String,
        privilege: String,
        object: String,
    },
    /// A write on the ledger or the state that no finding above names.
    TableWrite {
        runtime: String,
        table: String,
    },
    /// A trigger no compiled migration creates.
    ForeignTrigger {
        trigger: String,
        table: String,
    },
}

impl fmt::Display for RuntimeWriteAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const RERUN: &str = "then rerun the refused command";
        match self {
            Self::Superuser { runtime } => write!(
                formatter,
                "the runtime role {runtime} is a superuser and can write the activation \
                 ledger; run `ALTER ROLE {runtime} NOSUPERUSER`, {RERUN}"
            ),
            Self::MigrationRoleMember { runtime, migration } => write!(
                formatter,
                "the runtime role {runtime} is a member of the migration role {migration} and \
                 can write the activation ledger; run `REVOKE {migration} FROM {runtime}`, \
                 {RERUN}"
            ),
            Self::PrivilegedRoleMember { runtime, role } => write!(
                formatter,
                "the runtime role {runtime} is a member of {role}, which can write the \
                 activation ledger; run `REVOKE {role} FROM {runtime}`, {RERUN}"
            ),
            Self::Owner {
                object,
                runtime,
                migration,
            } => write!(
                formatter,
                "the runtime role {runtime} owns {object} and can write the activation ledger \
                 through it; run `REASSIGN OWNED BY {runtime} TO {migration}`, then \
                 `bregctl apply --package DIR` to reissue the runtime grants"
            ),
            Self::OwnerMember {
                object,
                owner,
                runtime,
            } => write!(
                formatter,
                "the runtime role {runtime} is a member of {owner}, which owns {object}, and \
                 can write the activation ledger through it; run `REVOKE {owner} FROM \
                 {runtime}`, {RERUN}"
            ),
            Self::Privilege {
                grantee,
                privilege,
                object,
            } => write!(
                formatter,
                "{grantee} holds {privilege} on {object}, which lets the runtime role write \
                 the activation ledger; run `REVOKE {privilege} ON {object} FROM {grantee}`, \
                 {RERUN}"
            ),
            Self::TableWrite { runtime, table } => write!(
                formatter,
                "the runtime role {runtime} can write {table}, which holds the activation \
                 ledger or the registry state; run `REVOKE ALL ON TABLE {table} FROM {runtime}` \
                 and revoke the membership that grants the write, {RERUN}"
            ),
            Self::ForeignTrigger { trigger, table } => write!(
                formatter,
                "the registry table {table} carries the trigger {trigger}, which no compiled \
                 migration creates; run `DROP TRIGGER {trigger} ON {table}`, {RERUN}"
            ),
        }
    }
}

/// The first way the split-role runtime role could write the activation
/// ledger or the registry state, or none. Callers run it only when the
/// configured roles differ; in single-role mode the runtime role is the
/// migration role and writes the ledger by design.
///
/// The catalog is read by role name, so the migration session of apply and
/// the runtime session of startup reach the same finding. A runtime role that
/// does not exist holds no authority; the grants apply issues name it.
pub async fn find_runtime_write_authority(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<Option<RuntimeWriteAuthority>> {
    let runtime = runtime_role.as_str().to_owned();
    let migration = migration_role.as_str().to_owned();
    let Some(role) = client
        .query_opt(
            "SELECT runtime.rolsuper,
                    pg_catalog.pg_has_role(runtime.oid, migration.oid, 'MEMBER')
               FROM pg_catalog.pg_roles runtime
               CROSS JOIN pg_catalog.pg_roles migration
              WHERE runtime.rolname = $1 AND migration.rolname = $2",
            &[&runtime, &migration],
        )
        .await?
    else {
        return Ok(None);
    };
    if role.get::<_, bool>(0) {
        return Ok(Some(RuntimeWriteAuthority::Superuser { runtime }));
    }
    if role.get::<_, bool>(1) {
        return Ok(Some(RuntimeWriteAuthority::MigrationRoleMember {
            runtime,
            migration,
        }));
    }
    // A superuser role writes every table once the runtime role sets it, and
    // `pg_write_all_data` grants INSERT, UPDATE, and DELETE on every table
    // without an entry in any ACL the checks below read.
    if let Some(privileged) = client
        .query_opt(
            "SELECT pg_catalog.quote_ident(privileged.rolname)
               FROM pg_catalog.pg_roles runtime
               JOIN pg_catalog.pg_roles privileged
                 ON (privileged.rolsuper OR privileged.rolname = 'pg_write_all_data')
                AND privileged.oid <> runtime.oid
              WHERE runtime.rolname = $1
                AND pg_catalog.pg_has_role(runtime.oid, privileged.oid, 'MEMBER')
              ORDER BY privileged.rolsuper DESC, privileged.rolname
              LIMIT 1",
            &[&runtime],
        )
        .await?
    {
        return Ok(Some(RuntimeWriteAuthority::PrivilegedRoleMember {
            runtime,
            role: privileged.get(0),
        }));
    }
    if let Some(owned) = client
        .query_opt(
            "WITH runtime AS (
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1
             ), owned(object, owner) AS (
                 SELECT 'SCHEMA ' || pg_catalog.quote_ident(n.nspname), n.nspowner
                   FROM pg_catalog.pg_namespace n
                  WHERE n.nspname = ANY($2::text[])
                 UNION ALL
                 SELECT CASE c.relkind
                            WHEN 'v' THEN 'VIEW '
                            WHEN 'S' THEN 'SEQUENCE '
                            ELSE 'TABLE '
                        END || pg_catalog.format('%I.%I', n.nspname, c.relname),
                        c.relowner
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = ANY($2::text[])
                    -- An index always has its table's owner, so the table
                    -- names the object an operator reassigns.
                    AND c.relkind NOT IN ('i', 'I')
                 UNION ALL
                 SELECT 'FUNCTION ' || pg_catalog.format('%I.%I', n.nspname, p.proname)
                        || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
                        p.proowner
                   FROM pg_catalog.pg_proc p
                   JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = ANY($2::text[])
             )
             SELECT o.object, owner.rolname::text, owner.oid = runtime.oid
               FROM owned o
               CROSS JOIN runtime
               JOIN pg_catalog.pg_roles owner ON owner.oid = o.owner
              WHERE pg_catalog.pg_has_role(runtime.oid, o.owner, 'MEMBER')
              ORDER BY owner.oid = runtime.oid DESC, o.object
              LIMIT 1",
            &[&runtime, &MANAGED_SCHEMAS],
        )
        .await?
    {
        let object: String = owned.get(0);
        return Ok(Some(if owned.get::<_, bool>(2) {
            RuntimeWriteAuthority::Owner {
                object,
                runtime,
                migration,
            }
        } else {
            RuntimeWriteAuthority::OwnerMember {
                object,
                owner: owned.get(1),
                runtime,
            }
        }));
    }
    if let Some(privilege) = client
        .query_opt(
            "WITH runtime AS (
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1
             ), held(object, privilege, grantee) AS (
                 SELECT 'SCHEMA ' || pg_catalog.quote_ident(n.nspname),
                        x.privilege_type,
                        x.grantee
                   FROM pg_catalog.pg_namespace n
                  CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) x
                  WHERE n.nspname = ANY($2::text[])
                    AND x.privilege_type = 'CREATE'
                 UNION ALL
                 SELECT 'TABLE ' || pg_catalog.format('%I.%I', n.nspname, c.relname),
                        x.privilege_type,
                        x.grantee
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  CROSS JOIN LATERAL pg_catalog.aclexplode(
                        COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) x
                  WHERE n.nspname = ANY($2::text[])
                    AND c.relkind IN ('r', 'v')
                    AND (x.privilege_type = 'TRIGGER'
                         OR (n.nspname = 'registry_internal'
                             AND c.relname = ANY($3::text[])
                             AND x.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')))
                 UNION ALL
                 SELECT 'TABLE ' || pg_catalog.format('%I.%I', n.nspname, c.relname),
                        x.privilege_type || ' (' || pg_catalog.quote_ident(a.attname) || ')',
                        x.grantee
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_catalog.pg_attribute a
                     ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                  CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x
                  WHERE n.nspname = 'registry_internal'
                    AND c.relname = ANY($3::text[])
                    AND x.privilege_type IN ('INSERT', 'UPDATE')
             )
             SELECT h.object,
                    h.privilege,
                    CASE WHEN h.grantee = 0 THEN 'PUBLIC'
                         ELSE pg_catalog.quote_ident(grantee.rolname) END
               FROM held h
               CROSS JOIN runtime
               LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = h.grantee
              WHERE h.grantee = 0 OR pg_catalog.pg_has_role(runtime.oid, h.grantee, 'MEMBER')
              ORDER BY h.object, h.privilege, 3
              LIMIT 1",
            &[&runtime, &MANAGED_SCHEMAS, &LEDGER_AND_STATE_TABLES],
        )
        .await?
    {
        return Ok(Some(RuntimeWriteAuthority::Privilege {
            object: privilege.get(0),
            privilege: privilege.get(1),
            grantee: privilege.get(2),
        }));
    }
    // PostgreSQL's own answer, whatever grants it, for a write path no
    // finding above names.
    if let Some(table) = client
        .query_opt(
            "SELECT 'registry_internal.' || pg_catalog.quote_ident(c.relname)
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               CROSS JOIN pg_catalog.pg_roles runtime
              WHERE n.nspname = 'registry_internal'
                AND c.relname = ANY($2::text[])
                AND runtime.rolname = $1
                AND pg_catalog.has_table_privilege(
                        runtime.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
              ORDER BY c.relname
              LIMIT 1",
            &[&runtime, &LEDGER_AND_STATE_TABLES],
        )
        .await?
    {
        return Ok(Some(RuntimeWriteAuthority::TableWrite {
            runtime,
            table: table.get(0),
        }));
    }
    // The compiled migrations create no trigger, so every trigger PostgreSQL
    // did not create for a constraint is foreign.
    if let Some(trigger) = client
        .query_opt(
            "SELECT pg_catalog.quote_ident(t.tgname),
                    pg_catalog.format('%I.%I', n.nspname, c.relname)
               FROM pg_catalog.pg_trigger t
               JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = ANY($1::text[])
                AND NOT t.tgisinternal
              ORDER BY 2, 1
              LIMIT 1",
            &[&MANAGED_SCHEMAS],
        )
        .await?
    {
        return Ok(Some(RuntimeWriteAuthority::ForeignTrigger {
            trigger: trigger.get(0),
            table: trigger.get(1),
        }));
    }
    Ok(None)
}

/// The tables that hold the activation ledger and the registry state.
const LEDGER_AND_STATE_TABLES: &[&str] = &[
    "registry_state",
    "registry_migrations",
    "registry_migration_steps",
    "registry_pre_ledger_package_positions",
];

async fn verify_schema_owner(
    client: &impl GenericClient,
    expected_role: &SqlIdentifier,
) -> Result<()> {
    let managed_schemas: &[&str] = &[
        "registry_data",
        "registry_derived",
        "registry_context",
        "registry_internal",
        "registry_source",
    ];
    let rows = client
        .query(
            "SELECT n.nspname, r.rolname
             FROM pg_catalog.pg_namespace n
             JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
             WHERE n.nspname = ANY($1::text[])
             ORDER BY n.nspname",
            &[&managed_schemas],
        )
        .await?;
    if rows.len() != managed_schemas.len()
        || rows
            .iter()
            .any(|row| row.get::<_, String>(1) != expected_role.as_str())
    {
        return Err(PostgresKernelError::RoleInvariant(
            "migration role does not own every managed schema",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governed_identifier_grammar_refuses_sql_syntax_and_case_folding() {
        for invalid in [
            "",
            "Uppercase",
            "9prefix",
            "has-hyphen",
            "quoted\"",
            "role;drop",
        ] {
            assert!(
                SqlIdentifier::parse(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(SqlIdentifier::parse(&"a".repeat(64)).is_err());
        assert_eq!(
            SqlIdentifier::parse("runtime_role_1")
                .expect("governed identifier parses")
                .as_str(),
            "runtime_role_1"
        );
    }
}
