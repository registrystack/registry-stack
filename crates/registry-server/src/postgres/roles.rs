// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

use crate::generated_ddl::POSTGIS_EXTENSION_SCHEMA;
use crate::physical_names::hex_prefix;

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
    let digest = Sha256::digest(
        format!(
            "registry-server/spatial-bbox-role/v1:{}",
            runtime_role.as_str()
        )
        .as_bytes(),
    );
    SqlIdentifier::parse(&format!("rs_bbox_{}", hex_prefix(&digest, 8)))
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
            "DO $registry_server_spatial$\n\
             BEGIN\n\
                 IF NOT EXISTS (\n\
                     SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{}'\n\
                 ) THEN\n\
                     CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;\n\
                 END IF;\n\
             END;\n\
             $registry_server_spatial$;\n\
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
    let valid_membership = row.get::<_, bool>(0)
        && !row.get::<_, bool>(1)
        && row.get::<_, bool>(2)
        && !row.get::<_, bool>(3)
        && !row.get::<_, bool>(4)
        && !row.get::<_, bool>(5)
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
