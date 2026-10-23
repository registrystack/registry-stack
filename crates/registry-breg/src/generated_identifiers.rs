// SPDX-License-Identifier: Apache-2.0

//! Transactional allocation for compiler-declared public record identifiers.
//!
//! The record UUID remains the engine's identity. These values are ordinary,
//! immutable record fields whose allocation and reservation join the mutation
//! transaction that first exposes them.

use serde_json::{Map, Value};
use tokio_postgres::types::ToSql;
use tokio_postgres::{GenericClient, Transaction};

use crate::model::{
    CompiledEntity, CompiledGeneratedIdentifier, CompiledGeneratedIdentifierStrategy,
    CompiledRegistry,
};
use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;

const MAX_ALLOCATION_ATTEMPTS: usize = 64;

pub(crate) const GENERATED_IDENTIFIER_TABLES: &[(&str, &[&str])] = &[
    ("registry_generated_identifier_reservations", &[]),
    ("registry_generated_identifier_counters", &[]),
];
pub(crate) const GENERATED_IDENTIFIER_SEQUENCE_FUNCTION: &str =
    "registry_internal.allocate_generated_identifier_sequence(text, text, jsonb)";
pub(crate) const GENERATED_IDENTIFIER_RESERVATION_FUNCTION: &str =
    "registry_internal.reserve_generated_identifier(text, text, jsonb, text)";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum GeneratedIdentifierError {
    #[error("generated identifier input is invalid")]
    InvalidInput,
    #[error("generated identifier space is exhausted")]
    Exhausted,
    #[error("generated identifier state is unavailable")]
    Unavailable,
}

impl From<GeneratedIdentifierError> for MutationError {
    fn from(error: GeneratedIdentifierError) -> Self {
        match error {
            GeneratedIdentifierError::InvalidInput => Self::InvalidRequest,
            GeneratedIdentifierError::Exhausted => Self::Conflict,
            GeneratedIdentifierError::Unavailable => Self::Unavailable,
        }
    }
}

pub(crate) fn registry_uses_generated_identifiers(registry: &CompiledRegistry) -> bool {
    registry
        .entities()
        .values()
        .any(|entity| entity.fields.values().any(|field| field.generate.is_some()))
}

/// Install the runtime-owned allocation state with the migration role.
///
/// Reservations are append-only for the runtime role. They keep an issued
/// value unavailable even if a record is later tombstoned or erased. Sequence
/// heads are separate mutable state and are advanced while their row is locked.
pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), GeneratedIdentifierError> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_generated_identifier_reservations (
                 entity_id text COLLATE pg_catalog.pg_c_utf8 NOT NULL CHECK (entity_id <> ''),
                 field_id text COLLATE pg_catalog.pg_c_utf8 NOT NULL CHECK (field_id <> ''),
                 scope_values jsonb NOT NULL CHECK (jsonb_typeof(scope_values) = 'array'),
                 generated_value text COLLATE pg_catalog.pg_c_utf8 NOT NULL,
                 reserved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (entity_id, field_id, scope_values, generated_value)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_generated_identifier_counters (
                 entity_id text COLLATE pg_catalog.pg_c_utf8 NOT NULL CHECK (entity_id <> ''),
                 field_id text COLLATE pg_catalog.pg_c_utf8 NOT NULL CHECK (field_id <> ''),
                 scope_values jsonb NOT NULL CHECK (jsonb_typeof(scope_values) = 'array'),
                 next_value numeric(20, 0) NOT NULL CHECK (next_value > 0),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (entity_id, field_id, scope_values)
             );
             CREATE OR REPLACE FUNCTION registry_internal.allocate_generated_identifier_sequence(
                 text, text, jsonb
             ) RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER
                SET search_path = pg_catalog, registry_internal AS $body$
                INSERT INTO registry_internal.registry_generated_identifier_counters
                    (entity_id, field_id, scope_values, next_value)
                VALUES ($1, $2, $3, 2)
                ON CONFLICT (entity_id, field_id, scope_values)
                DO UPDATE SET
                    next_value = registry_internal.registry_generated_identifier_counters.next_value + 1,
                    updated_at = transaction_timestamp()
                WHERE registry_internal.registry_generated_identifier_counters.next_value <= 9223372036854775807
                RETURNING (next_value - 1)::bigint;
             $body$;
             CREATE OR REPLACE FUNCTION registry_internal.reserve_generated_identifier(
                 text, text, jsonb, text
             ) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER
                SET search_path = pg_catalog, registry_internal AS $body$
                WITH reserved AS (
                    INSERT INTO registry_internal.registry_generated_identifier_reservations
                        (entity_id, field_id, scope_values, generated_value)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (entity_id, field_id, scope_values, generated_value) DO NOTHING
                    RETURNING 1
                )
                SELECT EXISTS (SELECT 1 FROM reserved);
             $body$;
             REVOKE ALL ON registry_internal.registry_generated_identifier_reservations,
                 registry_internal.registry_generated_identifier_counters FROM PUBLIC;
             REVOKE ALL ON FUNCTION registry_internal.allocate_generated_identifier_sequence(
                 text, text, jsonb
             ), registry_internal.reserve_generated_identifier(
                 text, text, jsonb, text
             ) FROM PUBLIC;",
        )
        .await
        .map_err(|_| GeneratedIdentifierError::Unavailable)?;

    let runtime_revoke = crate::postgres::RuntimeRevoke::detect(migration, runtime_role)
        .await
        .map_err(|_| GeneratedIdentifierError::Unavailable)?;
    let role = runtime_role.as_str();
    let grants = GENERATED_IDENTIFIER_TABLES
        .iter()
        .map(|(table, privileges)| {
            let qualified = format!("registry_internal.{table}");
            let grant = if privileges.is_empty() {
                String::new()
            } else {
                format!(
                    "GRANT {} ON {qualified} TO \"{role}\";",
                    privileges.join(", ")
                )
            };
            format!("{} {grant}", runtime_revoke.revoke_all_on(&qualified))
        })
        .collect::<Vec<_>>()
        .join("\n");
    migration
        .batch_execute(&format!(
            "{grants}
             {}
             {}
             GRANT EXECUTE ON FUNCTION registry_internal.allocate_generated_identifier_sequence(
                 text, text, jsonb
             ), registry_internal.reserve_generated_identifier(
                 text, text, jsonb, text
             ) TO \"{role}\";",
            runtime_revoke.revoke_all_on(
                "FUNCTION registry_internal.allocate_generated_identifier_sequence(text, text, jsonb)"
            ),
            runtime_revoke.revoke_all_on(
                "FUNCTION registry_internal.reserve_generated_identifier(text, text, jsonb, text)"
            ),
        ))
        .await
        .map_err(|_| GeneratedIdentifierError::Unavailable)?;
    Ok(())
}

/// Reserve every generated field for one create inside its owning transaction.
///
/// Callers must invoke this only after their idempotency replay check. The
/// function refuses caller-supplied generated values, resolves scopes from the
/// complete create field map, and adds only successfully reserved values.
pub(crate) async fn reserve_for_create(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    fields: &mut Map<String, Value>,
) -> Result<(), GeneratedIdentifierError> {
    if entity
        .fields
        .values()
        .any(|field| field.generate.is_some() && fields.contains_key(&field.id))
    {
        return Err(GeneratedIdentifierError::InvalidInput);
    }

    // Compiler validation rejects generated-on-generated scopes. Allocating in
    // field order therefore cannot make one generated value authority for the
    // scope of another.
    for field in entity.fields.values() {
        let Some(generation) = field.generate.as_ref() else {
            continue;
        };
        let scope_values = canonical_scope_values(transaction, entity, fields, generation).await?;
        let generated = match &generation.strategy {
            CompiledGeneratedIdentifierStrategy::Sequence { minimum_digits } => {
                reserve_sequence(
                    transaction,
                    &entity.id,
                    &field.id,
                    &scope_values,
                    &generation.prefix,
                    *minimum_digits,
                )
                .await?
            }
            CompiledGeneratedIdentifierStrategy::Random { length, alphabet } => {
                reserve_random(
                    transaction,
                    &entity.id,
                    &field.id,
                    &scope_values,
                    &generation.prefix,
                    *length,
                    alphabet,
                )
                .await?
            }
        };
        fields.insert(field.id.clone(), Value::String(generated));
    }
    Ok(())
}

/// Generated values and every field that partitions their namespace are
/// immutable after create. Proposal preparation, Action execution, and direct
/// mutation admission share this predicate so work cannot freeze only to fail
/// later at apply.
pub(crate) fn is_immutable_field(entity: &CompiledEntity, field_id: &str) -> bool {
    entity
        .fields
        .get(field_id)
        .is_some_and(|field| field.generate.is_some())
        || entity.fields.values().any(|field| {
            field
                .generate
                .as_ref()
                .is_some_and(|generation| generation.scope.iter().any(|scope| scope == field_id))
        })
}

async fn canonical_scope_values(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    fields: &Map<String, Value>,
    generation: &CompiledGeneratedIdentifier,
) -> Result<Value, GeneratedIdentifierError> {
    if generation.scope.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    let mut values = Vec::<Option<String>>::with_capacity(generation.scope.len());
    let mut projections = Vec::with_capacity(generation.scope.len());
    for field_id in &generation.scope {
        let field = entity
            .fields
            .get(field_id)
            .ok_or(GeneratedIdentifierError::InvalidInput)?;
        let value = fields
            .get(field_id)
            .filter(|value| !value.is_null())
            .ok_or(GeneratedIdentifierError::InvalidInput)?;
        values.push(
            crate::mutation::sql_value(value, &field.field_type)
                .map_err(|_| GeneratedIdentifierError::InvalidInput)?,
        );
        projections.push(format!(
            "to_jsonb({})",
            crate::mutation::typed_parameter(values.len(), &field.field_type)
        ));
    }
    let parameters = values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let sql = format!("SELECT jsonb_build_array({})", projections.join(", "));
    transaction
        .query_one(&sql, &parameters)
        .await
        .map(|row| row.get(0))
        .map_err(|_| GeneratedIdentifierError::Unavailable)
}

async fn reserve_sequence(
    transaction: &Transaction<'_>,
    entity_id: &str,
    field_id: &str,
    scope_values: &Value,
    prefix: &str,
    minimum_digits: u32,
) -> Result<String, GeneratedIdentifierError> {
    let minimum_digits =
        usize::try_from(minimum_digits).map_err(|_| GeneratedIdentifierError::InvalidInput)?;
    for _ in 0..MAX_ALLOCATION_ATTEMPTS {
        // The UPSERT takes the per-scope row lock. Its returned value is the
        // value owned by this transaction, so allocation never observes or
        // derives a candidate from the record table.
        let row = transaction
            .query_one(
                "SELECT registry_internal.allocate_generated_identifier_sequence($1, $2, $3)",
                &[&entity_id, &field_id, scope_values],
            )
            .await
            .map_err(|error| {
                if error.code()
                    == Some(&tokio_postgres::error::SqlState::NUMERIC_VALUE_OUT_OF_RANGE)
                {
                    GeneratedIdentifierError::Exhausted
                } else {
                    GeneratedIdentifierError::Unavailable
                }
            })?;
        let number: i64 = row
            .get::<_, Option<i64>>(0)
            .ok_or(GeneratedIdentifierError::Exhausted)?;
        let candidate = format!("{prefix}{number:0minimum_digits$}");
        if reserve(transaction, entity_id, field_id, scope_values, &candidate).await? {
            return Ok(candidate);
        }
    }
    Err(GeneratedIdentifierError::Exhausted)
}

async fn reserve_random(
    transaction: &Transaction<'_>,
    entity_id: &str,
    field_id: &str,
    scope_values: &Value,
    prefix: &str,
    length: u32,
    alphabet: &str,
) -> Result<String, GeneratedIdentifierError> {
    let alphabet = alphabet.as_bytes();
    if alphabet.len() < 2 || alphabet.len() > 128 || !alphabet.is_ascii() {
        return Err(GeneratedIdentifierError::InvalidInput);
    }
    let length = usize::try_from(length).map_err(|_| GeneratedIdentifierError::InvalidInput)?;
    if length == 0 {
        return Err(GeneratedIdentifierError::InvalidInput);
    }
    for _ in 0..MAX_ALLOCATION_ATTEMPTS {
        let suffix = random_suffix(length, alphabet)?;
        let candidate = format!("{prefix}{suffix}");
        if reserve(transaction, entity_id, field_id, scope_values, &candidate).await? {
            return Ok(candidate);
        }
    }
    Err(GeneratedIdentifierError::Exhausted)
}

fn random_suffix(length: usize, alphabet: &[u8]) -> Result<String, GeneratedIdentifierError> {
    let mut output = Vec::with_capacity(length);
    let alphabet_len = alphabet.len();
    let accepted_range = 256 - (256 % alphabet_len);
    let mut entropy = [0_u8; 64];
    while output.len() < length {
        getrandom::fill(&mut entropy).map_err(|_| GeneratedIdentifierError::Unavailable)?;
        for byte in entropy {
            let value = usize::from(byte);
            if value < accepted_range {
                output.push(alphabet[value % alphabet_len]);
                if output.len() == length {
                    break;
                }
            }
        }
    }
    String::from_utf8(output).map_err(|_| GeneratedIdentifierError::InvalidInput)
}

async fn reserve(
    transaction: &Transaction<'_>,
    entity_id: &str,
    field_id: &str,
    scope_values: &Value,
    generated_value: &str,
) -> Result<bool, GeneratedIdentifierError> {
    transaction
        .query_one(
            "SELECT registry_internal.reserve_generated_identifier($1, $2, $3, $4)",
            &[&entity_id, &field_id, scope_values, &generated_value],
        )
        .await
        .map(|row| row.get(0))
        .map_err(|_| GeneratedIdentifierError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_suffix_uses_only_the_declared_alphabet() {
        let suffix = random_suffix(512, b"ABC").expect("the test host supplies entropy");
        assert_eq!(suffix.len(), 512);
        assert!(suffix.bytes().all(|byte| b"ABC".contains(&byte)));
    }
}
