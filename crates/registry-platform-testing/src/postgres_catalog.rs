// SPDX-License-Identifier: Apache-2.0
//! Canonical PostgreSQL catalog snapshots for migration replay tests.

use std::collections::BTreeSet;

use serde_json::Value;
use tokio_postgres::Client;

const SCHEMA_PLACEHOLDER: &str = "<schema>";

const CATALOG_QUERIES: &[&str] = &[
    r#"
    SELECT jsonb_build_object(
        'kind', 'namespace',
        'schema', namespace.nspname,
        'owner', pg_catalog.pg_get_userbyid(namespace.nspowner),
        'acl', namespace.nspacl::text
    )
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = $1
    "#,
    r#"
    SELECT jsonb_build_object(
        'kind', 'relation',
        'schema', namespace.nspname,
        'name', relation.relname,
        'relationKind', relation.relkind::text,
        'persistence', relation.relpersistence::text,
        'rowSecurity', relation.relrowsecurity,
        'forceRowSecurity', relation.relforcerowsecurity,
        'replicaIdentity', relation.relreplident::text,
        'owner', pg_catalog.pg_get_userbyid(relation.relowner),
        'accessMethod', access_method.amname,
        'options', to_jsonb(relation.reloptions),
        'acl', relation.relacl::text,
        'comment', pg_catalog.obj_description(relation.oid, 'pg_class')
    )
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = relation.relam
    WHERE namespace.nspname = $1
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'column',
        'schema', namespace.nspname,
        'relation', relation.relname,
        'position', attribute.attnum,
        'name', attribute.attname,
        'type', pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
        'notNull', attribute.attnotnull,
        'identity', attribute.attidentity::text,
        'generated', attribute.attgenerated::text,
        'default', pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid, false),
        'collationSchema', collation_namespace.nspname,
        'collation', collation_row.collname,
        'storage', attribute.attstorage::text,
        'compression', attribute.attcompression::text,
        'statisticsTarget', attribute.attstattarget,
        'options', to_jsonb(attribute.attoptions),
        'acl', attribute.attacl::text
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_attrdef AS default_value
      ON default_value.adrelid = attribute.attrelid
     AND default_value.adnum = attribute.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = attribute.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_row.collnamespace
    WHERE namespace.nspname = $1
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'constraint',
        'schema', namespace.nspname,
        'relation', relation.relname,
        'name', constraint_row.conname,
        'constraintType', constraint_row.contype::text,
        'deferrable', constraint_row.condeferrable,
        'deferred', constraint_row.condeferred,
        'validated', constraint_row.convalidated,
        'noInherit', constraint_row.connoinherit,
        'definition', pg_catalog.pg_get_constraintdef(constraint_row.oid, false)
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_row.conrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = $1
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'index',
        'schema', namespace.nspname,
        'relation', relation.relname,
        'name', index_relation.relname,
        'accessMethod', access_method.amname,
        'unique', index_row.indisunique,
        'primary', index_row.indisprimary,
        'exclusion', index_row.indisexclusion,
        'immediate', index_row.indimmediate,
        'nullsNotDistinct', index_row.indnullsnotdistinct,
        'replicaIdentity', index_row.indisreplident,
        'valid', index_row.indisvalid,
        'ready', index_row.indisready,
        'live', index_row.indislive,
        'numberOfKeyAttributes', index_row.indnkeyatts,
        'numberOfAttributes', index_row.indnatts,
        'attributeNumbers', index_row.indkey::text,
        'operatorClasses', index_row.indclass::text,
        'collations', index_row.indcollation::text,
        'options', index_row.indoption::text,
        'keys', (
            SELECT jsonb_agg(
                pg_catalog.pg_get_indexdef(index_row.indexrelid, position, false)
                ORDER BY position
            )
            FROM pg_catalog.generate_series(1, index_row.indnatts) AS positions(position)
        ),
        'predicate', pg_catalog.pg_get_expr(index_row.indpred, index_row.indrelid, false),
        'relationOptions', to_jsonb(index_relation.reloptions),
        'tablespace', tablespace.spcname
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_index AS index_row
    JOIN pg_catalog.pg_class AS relation ON relation.oid = index_row.indrelid
    JOIN pg_catalog.pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_relation.relam
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = index_relation.reltablespace
    WHERE namespace.nspname = $1
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'trigger',
        'schema', namespace.nspname,
        'relation', relation.relname,
        'name', trigger_row.tgname,
        'enabled', trigger_row.tgenabled::text,
        'type', trigger_row.tgtype,
        'columns', trigger_row.tgattr::text,
        'arguments', pg_catalog.encode(trigger_row.tgargs, 'hex'),
        'when', pg_catalog.pg_get_expr(trigger_row.tgqual, trigger_row.tgrelid, false),
        'functionSchema', CASE
            WHEN function_namespace.nspname = $1 THEN '<schema>'
            ELSE function_namespace.nspname
        END,
        'function', function_row.proname,
        'functionArguments', pg_catalog.pg_get_function_identity_arguments(function_row.oid)
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_trigger AS trigger_row
    JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_row.tgrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = trigger_row.tgfoid
    JOIN pg_catalog.pg_namespace AS function_namespace
      ON function_namespace.oid = function_row.pronamespace
    WHERE namespace.nspname = $1
      AND NOT trigger_row.tgisinternal
    "#,
    r#"
    SELECT jsonb_build_object(
        'kind', 'function',
        'schema', namespace.nspname,
        'name', function_row.proname,
        'identityArguments', pg_catalog.pg_get_function_identity_arguments(function_row.oid),
        'arguments', pg_catalog.pg_get_function_arguments(function_row.oid),
        'result', pg_catalog.pg_get_function_result(function_row.oid),
        'language', language.lanname,
        'source', function_row.prosrc,
        'binary', function_row.probin,
        'functionKind', function_row.prokind::text,
        'volatility', function_row.provolatile::text,
        'parallel', function_row.proparallel::text,
        'strict', function_row.proisstrict,
        'securityDefiner', function_row.prosecdef,
        'leakproof', function_row.proleakproof,
        'returnsSet', function_row.proretset,
        'configuration', to_jsonb(function_row.proconfig),
        'owner', pg_catalog.pg_get_userbyid(function_row.proowner),
        'acl', function_row.proacl::text
    )
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function_row.pronamespace
    JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang
    WHERE namespace.nspname = $1
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'view',
        'schema', namespace.nspname,
        'name', relation.relname,
        'definition', pg_catalog.pg_get_viewdef(relation.oid, false)
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = $1
      AND relation.relkind IN ('v', 'm')
    "#,
    r#"
    SELECT jsonb_build_object(
        'kind', 'sequence',
        'schema', namespace.nspname,
        'name', relation.relname,
        'dataType', pg_catalog.format_type(sequence.seqtypid, NULL),
        'start', sequence.seqstart,
        'increment', sequence.seqincrement,
        'maximum', sequence.seqmax,
        'minimum', sequence.seqmin,
        'cache', sequence.seqcache,
        'cycle', sequence.seqcycle,
        'ownerRelation', owner_relation.relname,
        'ownerColumn', owner_attribute.attname,
        'dependencyType', dependency.deptype::text
    )
    FROM pg_catalog.pg_sequence AS sequence
    JOIN pg_catalog.pg_class AS relation ON relation.oid = sequence.seqrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_depend AS dependency
      ON dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND dependency.objid = relation.oid
     AND dependency.objsubid = 0
     AND dependency.deptype IN ('a', 'i')
    LEFT JOIN pg_catalog.pg_class AS owner_relation
      ON owner_relation.oid = dependency.refobjid
    LEFT JOIN pg_catalog.pg_attribute AS owner_attribute
      ON owner_attribute.attrelid = dependency.refobjid
     AND owner_attribute.attnum = dependency.refobjsubid
    WHERE namespace.nspname = $1
    "#,
    r#"
    WITH configured AS MATERIALIZED (
        SELECT pg_catalog.set_config(
            'search_path',
            pg_catalog.quote_ident($1) || ',pg_catalog',
            true
        )
    )
    SELECT jsonb_build_object(
        'kind', 'policy',
        'schema', namespace.nspname,
        'relation', relation.relname,
        'name', policy.polname,
        'command', policy.polcmd::text,
        'permissive', policy.polpermissive,
        'roles', (
            SELECT jsonb_agg(
                CASE role_id
                    WHEN 0 THEN 'public'
                    ELSE pg_catalog.pg_get_userbyid(role_id)
                END
                ORDER BY role_id
            )
            FROM pg_catalog.unnest(policy.polroles) AS roles(role_id)
        ),
        'using', pg_catalog.pg_get_expr(policy.polqual, policy.polrelid, false),
        'withCheck', pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, false)
    )
    FROM configured
    CROSS JOIN pg_catalog.pg_policy AS policy
    JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = $1
    "#,
];

/// Compare the schema-owned PostgreSQL catalog that two migration paths leave.
///
/// Schema names are fixture identity, so they are normalized structurally.
/// SQL expressions, defaults, function bodies, constraint literals and every
/// other catalog value are retained byte for byte. Table rows are deliberately
/// outside this helper: each product's replay test compares its meaningful
/// retained rows and ignores only its schema-migration ledger bookkeeping.
pub async fn verify_postgres_schema_equivalence(
    left_client: &Client,
    left_schema: &str,
    right_client: &Client,
    right_schema: &str,
) -> Result<(), String> {
    let left = postgres_schema_catalog(left_client, left_schema).await?;
    let right = postgres_schema_catalog(right_client, right_schema).await?;
    if left == right {
        return Ok(());
    }

    let left_set: BTreeSet<&str> = left.iter().map(String::as_str).collect();
    let right_set: BTreeSet<&str> = right.iter().map(String::as_str).collect();
    let only_left = left_set.difference(&right_set).copied().collect::<Vec<_>>();
    let only_right = right_set.difference(&left_set).copied().collect::<Vec<_>>();
    Err(format!(
        "PostgreSQL schemas {left_schema} and {right_schema} differ; only {left_schema}: {}; only {right_schema}: {}",
        display_difference(&only_left),
        display_difference(&only_right),
    ))
}

async fn postgres_schema_catalog(client: &Client, schema: &str) -> Result<Vec<String>, String> {
    let exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)",
            &[&schema],
        )
        .await
        .map_err(|error| format!("cannot inspect PostgreSQL schema {schema}: {error}"))?
        .get(0);
    if !exists {
        return Err(format!("PostgreSQL schema {schema} does not exist"));
    }

    let mut entries = Vec::new();
    for (query_index, query) in CATALOG_QUERIES.iter().enumerate() {
        let rows = client.query(*query, &[&schema]).await.map_err(|error| {
            let detail = error
                .as_db_error()
                .map_or_else(|| error.to_string(), |error| error.message().to_owned());
            format!(
                "cannot inspect PostgreSQL schema {schema} with catalog query {}: {detail}",
                query_index + 1
            )
        })?;
        for row in rows {
            let entry: Value = row.get(0);
            entries.push(normalize_schema_identity(entry, schema)?.to_string());
        }
    }
    entries.sort();
    Ok(entries)
}

fn normalize_schema_identity(mut row: Value, expected: &str) -> Result<Value, String> {
    let actual = row
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("a PostgreSQL catalog row has no schema identity: {row}"))?;
    if actual != expected {
        return Err(format!(
            "PostgreSQL catalog row for schema {actual} was returned while inspecting {expected}"
        ));
    }
    row["schema"] = Value::String(SCHEMA_PLACEHOLDER.to_owned());
    Ok(row)
}

fn display_difference(entries: &[&str]) -> String {
    if entries.is_empty() {
        return "none".to_owned();
    }
    entries.join(", ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{normalize_schema_identity, SCHEMA_PLACEHOLDER};

    #[test]
    fn schema_identity_normalization_changes_only_the_structural_schema_member() {
        let row = json!({
            "kind": "column",
            "schema": "left_fixture",
            "relation": "jobs",
            "name": "source",
            "default": "'left_fixture.domain'::text",
            "definition": "CHECK (source <> 'left_fixture')"
        });

        let normalized = normalize_schema_identity(row, "left_fixture").expect("known schema");

        assert_eq!(normalized["schema"], SCHEMA_PLACEHOLDER);
        assert_eq!(normalized["default"], "'left_fixture.domain'::text");
        assert_eq!(normalized["definition"], "CHECK (source <> 'left_fixture')");
    }

    #[test]
    fn schema_identity_normalization_refuses_a_row_from_another_schema() {
        let row = json!({"kind": "relation", "schema": "unexpected", "name": "jobs"});

        let report = normalize_schema_identity(row, "expected")
            .expect_err("a cross-schema catalog row is never normalized into the fixture");

        assert!(report.contains("unexpected"), "{report}");
        assert!(report.contains("expected"), "{report}");
    }
}
