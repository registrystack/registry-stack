// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use tokio_postgres::GenericClient;

use super::{PostgresKernelError, Result};

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
