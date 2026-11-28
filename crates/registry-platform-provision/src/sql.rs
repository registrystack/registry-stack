// SPDX-License-Identifier: Apache-2.0
//! Statement builders. Every builder returns text and runs nothing. The text
//! of each statement is the text `rstack dev` provisions with.

use crate::plan::SchemaLayout;

/// Lets a role holding CREATEROLE use the roles it creates. PostgreSQL 16 and
/// later grant such a creator only ADMIN on them, which is not enough for
/// `CREATE SCHEMA ... AUTHORIZATION` or `CREATE DATABASE ... OWNER`.
pub const CREATEROLE_SELF_GRANT: &str = "set,inherit";

pub fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// `verifier` is a SCRAM-SHA-256 verifier, never a password.
pub fn create_role_sql(role: &str, verifier: &str) -> String {
    format!(
        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD {}",
        quote_identifier(role),
        quote_literal(verifier)
    )
}

/// The login role without its `PASSWORD` clause, for the printed script.
pub(crate) fn create_role_printable_sql(role: &str) -> String {
    format!(
        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
        quote_identifier(role)
    )
}

pub fn create_nologin_role_sql(role: &str) -> String {
    format!(
        "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
        quote_identifier(role)
    )
}

pub fn create_database_sql(database: &str) -> String {
    format!(
        "CREATE DATABASE {} WITH ALLOW_CONNECTIONS false",
        quote_identifier(database)
    )
}

pub fn revoke_public_sql(database: &str) -> String {
    format!(
        "REVOKE ALL ON DATABASE {} FROM PUBLIC",
        quote_identifier(database)
    )
}

pub fn grant_connect_sql(database: &str, roles: &[&str]) -> String {
    let roles = roles
        .iter()
        .map(|role| quote_identifier(role))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "GRANT CONNECT ON DATABASE {} TO {roles}",
        quote_identifier(database)
    )
}

pub fn grant_create_sql(database: &str, migration: &str) -> String {
    format!(
        "GRANT CREATE ON DATABASE {} TO {}",
        quote_identifier(database),
        quote_identifier(migration)
    )
}

pub fn allow_connections_sql(database: &str) -> String {
    format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS true",
        quote_identifier(database)
    )
}

/// The three statements that close a new database to PUBLIC, open it to the
/// run's roles and then let it accept connections, in that order.
pub fn database_access_sql(database: &str, migration: &str, runtime: &str) -> String {
    format!(
        "{}; {}; {}",
        revoke_public_sql(database),
        grant_connect_sql(database, &distinct_roles(migration, runtime)),
        allow_connections_sql(database),
    )
}

pub fn btree_gist_sql() -> &'static str {
    "CREATE EXTENSION btree_gist"
}

pub fn owned_schema_sql(schema: &str, owner: &str) -> String {
    format!(
        "CREATE SCHEMA {schema} AUTHORIZATION {owner}; \
         REVOKE ALL ON SCHEMA {schema} FROM PUBLIC",
        schema = quote_identifier(schema),
        owner = quote_identifier(owner),
    )
}

pub fn public_schema_sql(migration: &str) -> String {
    format!(
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
         GRANT USAGE, CREATE ON SCHEMA public TO {}",
        quote_identifier(migration)
    )
}

/// Everything that runs inside the database apart from PostGIS: the one batch
/// `rstack dev` configures a fresh database with. `CreatedByApply` has none.
pub fn database_setup_sql(migration: &str, layout: &SchemaLayout, btree_gist: bool) -> String {
    match layout {
        SchemaLayout::Owned(schemas) => {
            let schemas = schemas
                .iter()
                .map(|schema| owned_schema_sql(schema, migration))
                .collect::<Vec<_>>()
                .join("; ");
            if btree_gist {
                format!("{}; {schemas}", btree_gist_sql())
            } else {
                schemas
            }
        }
        SchemaLayout::PublicForMigration => public_schema_sql(migration),
        SchemaLayout::CreatedByApply => String::new(),
    }
}

/// Administrator-run PostGIS setup: the extension in its own schema, usable by
/// both roles, and the bbox role the migration role may SET. The bbox role
/// itself is created earlier. `schema` is written unquoted, so the caller
/// checks it is a plain lower-case identifier.
pub fn postgis_prerequisites_sql(
    schema: &str,
    migration: &str,
    runtime: &str,
    bbox_role: &str,
) -> String {
    let roles = distinct_roles(migration, runtime)
        .iter()
        .map(|role| quote_identifier(role))
        .collect::<Vec<_>>()
        .join(", ");
    let migration = quote_identifier(migration);
    let bbox = quote_identifier(bbox_role);
    format!(
        "CREATE SCHEMA IF NOT EXISTS {schema};\n\
         REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;\n\
         CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA {schema};\n\
         GRANT USAGE ON SCHEMA {schema} TO {roles};\n\
         GRANT {bbox} TO {migration} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n\
         GRANT USAGE ON SCHEMA {schema} TO {bbox};"
    )
}

/// Single-role mode names one role once.
fn distinct_roles<'a>(migration: &'a str, runtime: &'a str) -> Vec<&'a str> {
    if migration == runtime {
        vec![migration]
    } else {
        vec![migration, runtime]
    }
}
